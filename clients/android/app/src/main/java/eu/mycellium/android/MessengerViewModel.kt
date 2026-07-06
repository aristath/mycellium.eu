package eu.mycellium.android

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.mycellium_sdk.Account
import uniffi.mycellium_sdk.Contact
import uniffi.mycellium_sdk.Conversation
import uniffi.mycellium_sdk.DeliveryState
import uniffi.mycellium_sdk.EventListener
import uniffi.mycellium_sdk.Group
import uniffi.mycellium_sdk.Message
import uniffi.mycellium_sdk.MyceliumClient
import uniffi.mycellium_sdk.PushPlatform
import uniffi.mycellium_sdk.SdkException

/** Which screen is currently shown (simple state-driven router — no nav lib). */
enum class Screen {
    LOADING, SETUP, ONBOARDING, CONVERSATIONS, THREAD, CONTACTS,
    GROUPS, GROUP_THREAD, PAIRING, SETTINGS,
}

/** Two-step onboarding: collect handle+email, then enter the emailed code. */
enum class OnboardingStage { DETAILS, CODE }

data class OnboardingState(
    val stage: OnboardingStage = OnboardingStage.DETAILS,
    val handle: String = "",
    val email: String = "",
    val pending: String = "",
    // Populated only when the directory runs in dev mode (no SMTP); shown as a
    // hint so local flows work without a real inbox.
    val devCode: String? = null,
)

data class UiState(
    val screen: Screen = Screen.LOADING,
    val busy: Boolean = false,
    val error: String? = null,
    val dirUrl: String = "",
    val queueUrl: String = "",
    val account: Account? = null,
    val onboarding: OnboardingState = OnboardingState(),
    val conversations: List<Conversation> = emptyList(),
    val openPeer: String? = null,
    val thread: List<Message> = emptyList(),
    // The message currently being replied to in the open 1:1 thread, or null.
    val replyTo: Message? = null,
    val contacts: List<Contact> = emptyList(),
    // A safety number to compare out of band, plus the peer it belongs to.
    val safetyNumber: Pair<String, String>? = null,
    // Groups the account belongs to, and the currently open group thread.
    val groups: List<Group> = emptyList(),
    val openGroupId: String? = null,
    val openGroupName: String = "",
    val groupThread: List<Message> = emptyList(),
    // Verification: this account's contact card (hex), shown out of band.
    val myCard: String? = null,
    // Pairing: the one-time offer minted on this (new) device, if any.
    val pairOffer: String? = null,
    // Transient status line for Settings/Pairing actions (backup, push, cards…).
    val status: String? = null,
)

/**
 * Drives every screen against the real SDK. All SDK methods BLOCK, so each one
 * runs on [Dispatchers.IO]; results are folded into [uiState] on the main
 * dispatcher. An [EventListener] is registered so inbound messages surface live
 * (the SDK fires `onMessage` from `sync()`), and a light poll calls `sync()` on
 * an interval until native push (#71) replaces it.
 */
class MessengerViewModel(app: Application) : AndroidViewModel(app) {

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    /** Lazily-built, shared client. Access only via [withClient] (off main). */
    private suspend fun client(): MyceliumClient = withContext(Dispatchers.IO) {
        ClientHolder.get(getApplication())
    }

    init {
        bootstrap()
    }

    /**
     * First launch of the process: build the client (off main), install the
     * listener, read persisted config + account, and route to the right screen.
     */
    private fun bootstrap() {
        viewModelScope.launch {
            _uiState.update { it.copy(screen = Screen.LOADING, busy = true) }
            try {
                val (account, dir, queue) = withContext(Dispatchers.IO) {
                    val c = ClientHolder.get(getApplication())
                    c.setListener(listener)
                    Triple(
                        c.account(),
                        c.getSetting(KEY_DIR_URL).orEmpty(),
                        c.getSetting(KEY_QUEUE_URL).orEmpty(),
                    )
                }
                val registered = account.handle.isNotEmpty()
                _uiState.update {
                    it.copy(
                        busy = false,
                        account = account,
                        dirUrl = dir,
                        queueUrl = queue,
                        screen = when {
                            registered -> Screen.CONVERSATIONS
                            dir.isNotEmpty() && queue.isNotEmpty() -> Screen.ONBOARDING
                            else -> Screen.SETUP
                        },
                    )
                }
                if (registered) {
                    refreshConversations()
                    startPolling()
                }
            } catch (e: Throwable) {
                _uiState.update { it.copy(busy = false, screen = Screen.SETUP, error = describe(e)) }
            }
        }
    }

    // ---- Setup -----------------------------------------------------------

    fun saveSetup(dirUrl: String, queueUrl: String) {
        val dir = dirUrl.trim()
        val queue = queueUrl.trim()
        if (dir.isEmpty() || queue.isEmpty()) {
            _uiState.update { it.copy(error = "Both URLs are required") }
            return
        }
        launchSdk { c ->
            c.setSetting(KEY_DIR_URL, dir)
            c.setSetting(KEY_QUEUE_URL, queue)
            _uiState.update {
                it.copy(dirUrl = dir, queueUrl = queue, screen = Screen.ONBOARDING)
            }
        }
    }

    // ---- Onboarding ------------------------------------------------------

    fun updateOnboarding(handle: String? = null, email: String? = null) {
        _uiState.update {
            it.copy(
                onboarding = it.onboarding.copy(
                    handle = handle ?: it.onboarding.handle,
                    email = email ?: it.onboarding.email,
                ),
            )
        }
    }

    /** Onboarding step 1: start the email-verified claim of the handle. */
    fun startEmailVerification() {
        val s = _uiState.value
        val handle = s.onboarding.handle.trim()
        val email = s.onboarding.email.trim()
        if (handle.isEmpty() || email.isEmpty()) {
            _uiState.update { it.copy(error = "Handle and email are required") }
            return
        }
        launchSdk { c ->
            val verification = c.startEmailVerification(s.dirUrl, handle, email)
            _uiState.update {
                it.copy(
                    onboarding = it.onboarding.copy(
                        stage = OnboardingStage.CODE,
                        pending = verification.pending,
                        devCode = verification.devCode,
                    ),
                )
            }
        }
    }

    /** Onboarding step 2: confirm the code, then publish the record. */
    fun confirmAndRegister(code: String) {
        val s = _uiState.value
        val handle = s.onboarding.handle.trim()
        val trimmed = code.trim()
        if (trimmed.isEmpty()) {
            _uiState.update { it.copy(error = "Enter the verification code") }
            return
        }
        launchSdk { c ->
            c.confirmEmailVerification(s.dirUrl, s.onboarding.pending, trimmed)
            // Publish the signed directory record. Display name defaults to the
            // handle here; a fuller UI could collect a separate name.
            c.register(s.dirUrl, s.queueUrl, handle, handle)
            val account = c.account()
            _uiState.update {
                it.copy(account = account, screen = Screen.CONVERSATIONS)
            }
            refreshConversationsBlocking(c)
        }.invokeOnCompletion { if (_uiState.value.screen == Screen.CONVERSATIONS) startPolling() }
    }

    // ---- Conversations + thread -----------------------------------------

    fun refreshConversations() = launchSdk { c -> refreshConversationsBlocking(c) }

    private fun refreshConversationsBlocking(c: MyceliumClient) {
        val convos = c.conversations()
        _uiState.update { it.copy(conversations = convos) }
    }

    fun openThread(peer: String) {
        launchSdk { c ->
            val messages = c.thread(peer)
            _uiState.update {
                it.copy(openPeer = peer, thread = messages, replyTo = null, screen = Screen.THREAD)
            }
        }
    }

    /**
     * Send into the open 1:1 thread. If a message is staged for reply, this sends
     * a threaded [MyceliumClient.reply]; otherwise a plain [MyceliumClient.sendText].
     */
    fun sendText(text: String) {
        val peer = _uiState.value.openPeer ?: return
        val body = text.trim()
        if (body.isEmpty()) return
        val replyTo = _uiState.value.replyTo
        launchSdk { c ->
            // Returns the stored Message with an optimistic DeliveryState
            // (SENT/QUEUED) so the UI can render a pending tick immediately.
            if (replyTo != null) c.reply(peer, replyTo.id, body) else c.sendText(peer, body)
            val messages = c.thread(peer)
            _uiState.update { it.copy(thread = messages, replyTo = null) }
        }
    }

    /** Stage a message to reply to (shows a reply banner above the composer). */
    fun startReply(message: Message) = _uiState.update { it.copy(replyTo = message) }

    fun cancelReply() = _uiState.update { it.copy(replyTo = null) }

    /** Quick-emoji reaction to a message in the open 1:1 thread. */
    fun reactTo(targetId: String, emoji: String) {
        val peer = _uiState.value.openPeer ?: return
        launchSdk { c ->
            c.react(peer, targetId, emoji)
            val messages = c.thread(peer)
            _uiState.update { it.copy(thread = messages) }
        }
    }

    /** Delete one of our own messages for everyone in the open 1:1 thread. */
    fun deleteOwn(targetId: String) {
        val peer = _uiState.value.openPeer ?: return
        launchSdk { c ->
            c.deleteMessage(peer, targetId)
            val messages = c.thread(peer)
            _uiState.update { it.copy(thread = messages) }
        }
    }

    /** Attach a file to the open 1:1 thread: read the picked Uri's bytes and send. */
    fun sendFile(uri: Uri) {
        val peer = _uiState.value.openPeer ?: return
        launchSdk { c ->
            val resolver = getApplication<Application>().contentResolver
            val name = queryDisplayName(uri) ?: "attachment"
            val mime = resolver.getType(uri) ?: "application/octet-stream"
            val data = resolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw SdkException.InvalidInput("could not read the selected file")
            c.sendFile(peer, name, mime, data)
            val messages = c.thread(peer)
            _uiState.update { it.copy(thread = messages) }
        }
    }

    /** Best-effort human name for a content Uri (falls back to the last path segment). */
    private fun queryDisplayName(uri: Uri): String? {
        val resolver = getApplication<Application>().contentResolver
        return runCatching {
            resolver.query(uri, null, null, null, null)?.use { cursor ->
                val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && cursor.moveToFirst()) cursor.getString(idx) else null
            }
        }.getOrNull() ?: uri.lastPathSegment
    }

    /** Foreground receive: drain the queue, decrypt, persist, refresh visible view. */
    fun syncNow() {
        launchSdk { c ->
            c.sync()
            refreshVisibleBlocking(c)
        }
    }

    // ---- Contacts + verification ----------------------------------------

    fun openContacts() {
        launchSdk { c ->
            val contacts = c.contacts()
            _uiState.update { it.copy(contacts = contacts, screen = Screen.CONTACTS) }
        }
    }

    fun addContact(nickname: String, handle: String) {
        val nick = nickname.trim()
        val h = handle.trim()
        if (nick.isEmpty() || h.isEmpty()) {
            _uiState.update { it.copy(error = "Nickname and handle are required") }
            return
        }
        launchSdk { c ->
            c.addContact(nick, h)
            val contacts = c.contacts()
            _uiState.update { it.copy(contacts = contacts) }
        }
    }

    fun showSafetyNumber(peerHandle: String) {
        launchSdk { c ->
            val number = c.safetyNumber(peerHandle)
            _uiState.update { it.copy(safetyNumber = peerHandle to number) }
        }
    }

    fun clearSafetyNumber() = _uiState.update { it.copy(safetyNumber = null) }

    /** Pin the wallet the directory serves for [peer] now as verified. */
    fun markVerified(peer: String) {
        launchSdk { c ->
            c.markVerified(peer)
            val contacts = c.contacts()
            _uiState.update { it.copy(contacts = contacts, status = "$peer marked verified.") }
        }
    }

    // ---- Groups ----------------------------------------------------------

    fun openGroups() {
        launchSdk { c ->
            val groups = c.groups()
            _uiState.update { it.copy(groups = groups, screen = Screen.GROUPS) }
        }
    }

    fun refreshGroups() = launchSdk { c ->
        val groups = c.groups()
        _uiState.update { it.copy(groups = groups) }
    }

    /** Create a group from a name + comma-separated member handles, then open it. */
    fun createGroup(name: String, membersCsv: String) {
        val groupName = name.trim()
        if (groupName.isEmpty()) {
            _uiState.update { it.copy(error = "Group name is required") }
            return
        }
        val members = membersCsv.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        launchSdk { c ->
            val id = c.groupCreate(groupName, members)
            val groups = c.groups()
            val messages = c.groupThread(id)
            _uiState.update {
                it.copy(
                    groups = groups,
                    openGroupId = id,
                    openGroupName = groupName,
                    groupThread = messages,
                    screen = Screen.GROUP_THREAD,
                )
            }
        }
    }

    fun openGroupThread(groupId: String, name: String) {
        launchSdk { c ->
            val messages = c.groupThread(groupId)
            _uiState.update {
                it.copy(
                    openGroupId = groupId,
                    openGroupName = name,
                    groupThread = messages,
                    screen = Screen.GROUP_THREAD,
                )
            }
        }
    }

    fun sendGroupText(text: String) {
        val groupId = _uiState.value.openGroupId ?: return
        val body = text.trim()
        if (body.isEmpty()) return
        launchSdk { c ->
            c.groupSend(groupId, body)
            val messages = c.groupThread(groupId)
            _uiState.update { it.copy(groupThread = messages) }
        }
    }

    fun leaveGroup() {
        val groupId = _uiState.value.openGroupId ?: return
        launchSdk { c ->
            c.groupLeave(groupId)
            val groups = c.groups()
            _uiState.update {
                it.copy(
                    groups = groups,
                    openGroupId = null,
                    openGroupName = "",
                    groupThread = emptyList(),
                    screen = Screen.GROUPS,
                )
            }
        }
    }

    // ---- Verification: contact cards -------------------------------------

    /** Load this account's contact card (hex) to show a peer out of band. */
    fun loadContactCard() {
        launchSdk { c ->
            val card = c.contactCard()
            _uiState.update { it.copy(myCard = card) }
        }
    }

    /** Verify a peer's pasted contact card; on a match the handle is verified. */
    fun verifyCard(card: String) {
        val trimmed = card.trim()
        if (trimmed.isEmpty()) return
        launchSdk { c ->
            val handle = c.verifyCard(trimmed)
            val contacts = c.contacts()
            _uiState.update { it.copy(contacts = contacts, status = "Verified $handle.") }
        }
    }

    // ---- Seedless device pairing -----------------------------------------

    /** Open the pairing screen (a new device mints the offer, an existing device approves). */
    fun openPairing() = _uiState.update { it.copy(pairOffer = null, screen = Screen.PAIRING) }

    /** **New device**: mint a one-time pairing offer to show an existing device. */
    fun makePairOffer() {
        val queue = _uiState.value.queueUrl
        launchSdk { c ->
            val offer = c.pairOffer(queue)
            _uiState.update { it.copy(pairOffer = offer) }
        }
    }

    /** **New device**: poll the rendezvous once; adopt the account on success. */
    fun pollPairing() {
        val queue = _uiState.value.queueUrl
        launchSdk { c ->
            val adopted = c.pairPoll(queue)
            if (adopted != null && adopted.handle.isNotEmpty()) {
                _uiState.update {
                    it.copy(
                        account = adopted,
                        status = "Paired as ${adopted.handle}.",
                        screen = Screen.CONVERSATIONS,
                    )
                }
                refreshConversationsBlocking(c)
            } else {
                _uiState.update { it.copy(status = "No approval yet — keep polling.") }
            }
        }
    }

    /** **Existing device**: approve a new device's pasted pairing offer. */
    fun approveDevice(offer: String) {
        val trimmed = offer.trim()
        if (trimmed.isEmpty()) return
        val queue = _uiState.value.queueUrl
        launchSdk { c ->
            c.pairApprove(trimmed, queue)
            _uiState.update { it.copy(status = "Device approved — it can now adopt this account.") }
        }
    }

    // ---- Settings: backup / push -----------------------------------------

    fun openSettings() = _uiState.update { it.copy(status = null, screen = Screen.SETTINGS) }

    /** Export the encrypted store snapshot to a user-picked Uri. */
    fun exportBackup(target: Uri) {
        launchSdk { c ->
            val bytes = c.exportBackup()
            val resolver = getApplication<Application>().contentResolver
            resolver.openOutputStream(target)?.use { it.write(bytes) }
                ?: throw SdkException.Storage("could not open the chosen file for writing")
            _uiState.update { it.copy(status = "Backup exported (${bytes.size} bytes).") }
        }
    }

    /** Restore a store snapshot from a user-picked Uri, then refresh visible lists. */
    fun importBackup(source: Uri) {
        launchSdk { c ->
            val resolver = getApplication<Application>().contentResolver
            val bytes = resolver.openInputStream(source)?.use { it.readBytes() }
                ?: throw SdkException.InvalidInput("could not read the chosen backup file")
            c.importBackup(bytes)
            val convos = c.conversations()
            val contacts = c.contacts()
            val groups = c.groups()
            _uiState.update {
                it.copy(
                    conversations = convos,
                    contacts = contacts,
                    groups = groups,
                    status = "Backup imported.",
                )
            }
        }
    }

    /** Register a UnifiedPush endpoint so the queue can wake this device contentlessly. */
    fun registerUnifiedPush(endpoint: String) {
        val trimmed = endpoint.trim()
        if (trimmed.isEmpty()) {
            _uiState.update { it.copy(status = "Paste a UnifiedPush endpoint URL first.") }
            return
        }
        launchSdk { c ->
            c.registerPush(PushPlatform.UnifiedPush, trimmed)
            _uiState.update { it.copy(status = "UnifiedPush endpoint registered.") }
        }
    }

    fun clearStatus() = _uiState.update { it.copy(status = null) }

    // ---- Navigation helpers ---------------------------------------------

    fun back() {
        _uiState.update {
            when (it.screen) {
                Screen.THREAD, Screen.CONTACTS, Screen.GROUPS, Screen.SETTINGS, Screen.PAIRING ->
                    it.copy(screen = Screen.CONVERSATIONS, openPeer = null, replyTo = null)
                Screen.GROUP_THREAD ->
                    it.copy(screen = Screen.GROUPS, openGroupId = null, openGroupName = "")
                else -> it
            }
        }
    }

    fun dismissError() = _uiState.update { it.copy(error = null) }

    /** Called from the Activity's ON_RESUME: pull anything that arrived while away. */
    fun onResume() {
        if (_uiState.value.account?.handle?.isNotEmpty() == true) syncNow()
    }

    // ---- Live events + polling ------------------------------------------

    private val listener = object : EventListener {
        override fun onMessage(message: Message) {
            // Fired from a Rust thread inside sync(); marshal a UI refresh.
            viewModelScope.launch { launchSdk { c -> refreshVisibleBlocking(c) } }
        }

        override fun onDelivery(messageId: String, state: DeliveryState) {
            viewModelScope.launch { launchSdk { c -> refreshVisibleBlocking(c) } }
        }

        override fun onKeyChange(handle: String) {
            // A peer's key changed — surface a safety warning (possible MITM or a
            // legitimate recovery; the user re-verifies out of band).
            _uiState.update {
                it.copy(error = "Safety warning: the key for \"$handle\" changed. Re-verify out of band.")
            }
        }

        override fun onPairing(event: String) { /* progress UI for QR pairing, out of MVP scope */ }
    }

    private var polling = false

    /** Light foreground poll until native push (#71) lands. Never busy-polls. */
    private fun startPolling() {
        if (polling) return
        polling = true
        viewModelScope.launch {
            while (true) {
                delay(POLL_INTERVAL_MS)
                val screen = _uiState.value.screen
                if (screen == Screen.CONVERSATIONS || screen == Screen.THREAD ||
                    screen == Screen.GROUPS || screen == Screen.GROUP_THREAD
                ) {
                    try {
                        withContext(Dispatchers.IO) {
                            val c = ClientHolder.get(getApplication())
                            c.sync()
                            refreshVisibleBlocking(c)
                        }
                    } catch (_: Throwable) {
                        // Transient network errors while polling are non-fatal.
                    }
                }
            }
        }
    }

    /** Refresh whichever list the user is currently looking at. */
    private fun refreshVisibleBlocking(c: MyceliumClient) {
        when (_uiState.value.screen) {
            Screen.THREAD -> _uiState.value.openPeer?.let { peer ->
                val messages = c.thread(peer)
                val convos = c.conversations()
                _uiState.update { it.copy(thread = messages, conversations = convos) }
            }
            Screen.GROUP_THREAD -> _uiState.value.openGroupId?.let { gid ->
                val messages = c.groupThread(gid)
                val groups = c.groups()
                _uiState.update { it.copy(groupThread = messages, groups = groups) }
            }
            Screen.GROUPS -> {
                val groups = c.groups()
                _uiState.update { it.copy(groups = groups) }
            }
            else -> {
                val convos = c.conversations()
                _uiState.update { it.copy(conversations = convos) }
            }
        }
    }

    // ---- SDK call plumbing ----------------------------------------------

    /**
     * Run a blocking SDK block on [Dispatchers.IO], toggling [UiState.busy] and
     * turning any [SdkException] into a user-facing [UiState.error]. Returns the
     * launched Job so callers can chain (e.g. start polling on completion).
     */
    private fun launchSdk(block: suspend (MyceliumClient) -> Unit) =
        viewModelScope.launch {
            _uiState.update { it.copy(busy = true) }
            try {
                withContext(Dispatchers.IO) { block(client()) }
            } catch (e: Throwable) {
                _uiState.update { it.copy(error = describe(e)) }
            } finally {
                _uiState.update { it.copy(busy = false) }
            }
        }

    private companion object {
        const val KEY_DIR_URL = "dir_url"
        const val KEY_QUEUE_URL = "queue_url"
        const val POLL_INTERVAL_MS = 12_000L
    }
}

/** Map an [SdkException] variant to a concise, user-facing message. */
internal fun describe(e: Throwable): String = when (e) {
    is SdkException.NotRegistered -> "You need to register first."
    is SdkException.Network -> "Network error: ${e.msg}"
    is SdkException.Storage -> "Storage error: ${e.msg}"
    is SdkException.Crypto -> "Security error: ${e.msg}"
    is SdkException.InvalidInput -> "Invalid input: ${e.msg}"
    is SdkException.IdentityChanged ->
        "Safety warning: the identity for \"${e.handle}\" changed. Re-verify out of band."
    else -> e.message ?: e.javaClass.simpleName
}
