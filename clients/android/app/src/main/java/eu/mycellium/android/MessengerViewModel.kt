package eu.mycellium.android

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import uniffi.mycellium_mobile.ClientState
import uniffi.mycellium_mobile.ContactInfo
import uniffi.mycellium_mobile.ContactSecurityInfo
import uniffi.mycellium_mobile.ConversationInfo
import uniffi.mycellium_mobile.DeliveryState
import uniffi.mycellium_mobile.EventKind
import uniffi.mycellium_mobile.MessageInfo
import uniffi.mycellium_mobile.MobileClient
import uniffi.mycellium_mobile.ProfileInfo

data class MessengerUiState(
    val initialized: Boolean = false,
    val busy: Boolean = false,
    val clientState: ClientState = ClientState.NEEDS_LOGIN,
    val loginRequested: Boolean = false,
    val error: String? = null,
    val notice: String? = null,
    val conversations: List<ConversationInfo> = emptyList(),
    val contacts: List<ContactInfo> = emptyList(),
    val profile: ProfileInfo? = null,
    val pendingCount: ULong = 0u,
    val selectedUserId: String? = null,
    val selectedTitle: String = "",
    val messages: List<MessageInfo> = emptyList(),
    val security: ContactSecurityInfo? = null,
    val startupError: String? = null,
)

class MessengerViewModel(application: Application) : AndroidViewModel(application) {
    private companion object {
        const val TAG = "Mycellium"
    }

    private val identityStore = AndroidIdentityStore(application)
    private val mutableState = MutableStateFlow(MessengerUiState())
    val state: StateFlow<MessengerUiState> = mutableState.asStateFlow()
    private var client: MobileClient? = null

    init {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                val dataDir = application.filesDir.resolve("mycellium").absolutePath
                val opened = MobileClient.open(dataDir, identityStore.load(), null)
                client = opened
                refreshAll()
                opened
            }.onSuccess {
                mutableState.update { it.copy(initialized = true, startupError = null) }
                pollEvents()
            }.onFailure { error ->
                Log.e(TAG, "mobile client failed to open", error)
                client = null
                showError(error)
            }
        }
    }

    fun requestLogin(email: String) = action {
        require(email.isNotBlank()) { "Enter your email address" }
        requireClient().requestEmailLogin(email.trim())
        mutableState.update {
            it.copy(loginRequested = true, notice = "Check your email for the login code")
        }
    }

    fun confirmLogin(code: String) = action {
        require(code.isNotBlank()) { "Enter the code from your email" }
        val result = requireClient().confirmEmailLogin(code.trim())
        result.identitySecret?.let { secret ->
            try {
                identityStore.save(secret)
            } finally {
                secret.fill(0)
            }
        }
        mutableState.update {
            it.copy(
                loginRequested = false,
                notice = if (result.created) "Account created" else "This device is active",
            )
        }
        refreshAll()
    }

    fun confirmLoginLink(link: String) = action {
        val result = requireClient().confirmEmailLoginLink(link)
        result.identitySecret?.let { secret ->
            try {
                identityStore.save(secret)
            } finally {
                secret.fill(0)
            }
        }
        mutableState.update {
            it.copy(
                loginRequested = false,
                notice = if (result.created) "Account created" else "This device is active",
            )
        }
        refreshAll()
    }

    fun saveProfile(handle: String, displayName: String) = action {
        requireClient().saveProfile(handle, displayName)
        mutableState.update { it.copy(notice = "Profile saved") }
        refreshAll()
    }

    fun addContact(card: String, nickname: String) = action {
        require(card.isNotBlank()) { "Paste a connection card" }
        val contact = requireClient().addContact(card.trim(), nickname.trim().ifEmpty { null })
        mutableState.update { it.copy(notice = "${contact.nickname} added") }
        refreshAll()
    }

    fun removeContact(contact: ContactInfo) = action {
        requireClient().removeContact(contact.nickname)
        mutableState.update {
            it.copy(security = null, selectedUserId = null, notice = "Person removed")
        }
        refreshAll()
    }

    fun openConversation(userId: String, title: String) = action {
        mutableState.update {
            it.copy(selectedUserId = userId, selectedTitle = title, security = null)
        }
        refreshMessages()
    }

    fun closeConversation() {
        mutableState.update { it.copy(selectedUserId = null, selectedTitle = "", messages = emptyList()) }
    }

    fun sendMessage(text: String) = action {
        val userId = mutableState.value.selectedUserId ?: error("Choose a conversation")
        val result = requireClient().sendText(userId, text)
        mutableState.update {
            it.copy(
                notice = if (result == DeliveryState.DELIVERED) {
                    "Delivered"
                } else {
                    "Direct connection unavailable. This device will keep trying."
                },
            )
        }
        refreshAll()
        refreshMessages()
    }

    fun retryPending() = action {
        val waiting = requireClient().retryPending()
        mutableState.update {
            it.copy(notice = if (waiting == 0uL) "Pending messages delivered" else "$waiting still pending")
        }
        refreshAll()
    }

    fun showSecurity(userId: String) = action {
        val security = requireClient().contactSecurity(userId)
        mutableState.update { it.copy(security = security) }
    }

    fun dismissSecurity() {
        mutableState.update { it.copy(security = null) }
    }

    fun verifyContact(userId: String) = action {
        requireClient().verifyContact(userId)
        mutableState.update { it.copy(notice = "Identity verified", security = null) }
        refreshAll()
    }

    fun acceptIdentityChange(userId: String) = action {
        requireClient().acceptIdentityChange(userId)
        mutableState.update { it.copy(notice = "New identity accepted", security = null) }
        refreshAll()
    }

    fun setContactBlocked(userId: String, blocked: Boolean) = action {
        val current = requireClient()
        current.setContactBlocked(userId, blocked)
        val security = current.contactSecurity(userId)
        mutableState.update {
            it.copy(
                notice = if (blocked) "Person blocked" else "Person unblocked",
                security = security,
            )
        }
    }

    fun clearMessage() {
        mutableState.update { it.copy(error = null, notice = null) }
    }

    fun restartLogin() {
        mutableState.update { it.copy(loginRequested = false, error = null, notice = null) }
    }

    fun onForeground() {
        if (client == null) return
        action {
            runCatching { requireClient().refreshConnectivity() }
            requireClient().refreshDeviceStatus()
            refreshAll()
        }
    }

    private fun action(block: suspend () -> Unit) {
        if (client == null) {
            mutableState.update {
                it.copy(error = it.startupError ?: "Mycellium is still starting")
            }
            return
        }
        if (mutableState.value.busy) {
            return
        }
        mutableState.update { it.copy(busy = true, error = null, notice = null) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { block() }
                .onFailure { error ->
                    Log.e(TAG, "action failed", error)
                    showError(error)
                }
            mutableState.update { it.copy(busy = false) }
        }
    }

    private suspend fun refreshAll() {
        val current = requireClient()
        val state = current.state()
        val ready = state == ClientState.READY || state == ClientState.REPLACED
        val profile = if (ready) current.profile() else null
        val conversations = if (ready) current.conversations() else emptyList()
        val contacts = if (ready) current.contacts() else emptyList()
        val pending = if (ready) current.pendingCount() else 0u
        mutableState.update {
            it.copy(
                clientState = state,
                profile = profile,
                conversations = conversations,
                contacts = contacts,
                pendingCount = pending,
            )
        }
    }

    private suspend fun refreshMessages() {
        val userId = mutableState.value.selectedUserId ?: return
        val messages = requireClient().messages(userId)
        mutableState.update { it.copy(messages = messages) }
    }

    private suspend fun pollEvents() {
        while (true) {
            delay(1_000)
            val events = runCatching { requireClient().pollEvents() }.getOrDefault(emptyList())
            if (events.isNotEmpty()) {
                val latest = events.last()
                mutableState.update {
                    it.copy(
                        notice = if (latest.kind == EventKind.ERROR) null else latest.message,
                        error = if (latest.kind == EventKind.ERROR) latest.message else null,
                    )
                }
                runCatching {
                    refreshAll()
                    refreshMessages()
                }
            }
        }
    }

    private fun requireClient(): MobileClient = client ?: error("Mycellium is still starting")

    private fun showError(error: Throwable) {
        val startupError = if (client == null) error.message ?: "Could not open this device" else null
        mutableState.update {
            it.copy(
                initialized = true,
                busy = false,
                startupError = startupError,
                error = error.message ?: "Something went wrong",
                notice = null,
            )
        }
    }
}
