package eu.mycellium.android.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import eu.mycellium.android.MessengerViewModel
import eu.mycellium.android.Screen
import eu.mycellium.android.UiState
import eu.mycellium.android.OnboardingStage
import uniffi.mycellium_sdk.Contact
import uniffi.mycellium_sdk.Conversation
import uniffi.mycellium_sdk.DeliveryState
import uniffi.mycellium_sdk.Group
import uniffi.mycellium_sdk.Message

/** Quick reactions offered under each message (mirrors the desktop client). */
private val QUICK_REACTS = listOf("👍", "❤️", "😂", "🎉", "🙏")

/**
 * Top-level router. Picks a screen from [UiState.screen], overlays a busy
 * spinner and an error dialog, and wires ON_RESUME to a foreground `sync()`.
 */
@Composable
fun AppRoot(state: UiState, vm: MessengerViewModel, modifier: Modifier = Modifier) {
    // Foreground receive: sync when the app resumes.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) vm.onResume()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Column(modifier = modifier.fillMaxSize()) {
        when (state.screen) {
            Screen.LOADING -> LoadingScreen()
            Screen.SETUP -> SetupScreen(state, vm)
            Screen.ONBOARDING -> OnboardingScreen(state, vm)
            Screen.CONVERSATIONS -> ConversationsScreen(state, vm)
            Screen.THREAD -> ThreadScreen(state, vm)
            Screen.CONTACTS -> ContactsScreen(state, vm)
            Screen.GROUPS -> GroupsScreen(state, vm)
            Screen.GROUP_THREAD -> GroupThreadScreen(state, vm)
            Screen.PAIRING -> PairingScreen(state, vm)
            Screen.SETTINGS -> SettingsScreen(state, vm)
        }
    }

    if (state.busy && state.screen != Screen.LOADING) {
        Surface(color = MaterialTheme.colorScheme.scrim.copy(alpha = 0.15f)) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) { CircularProgressIndicator() }
        }
    }

    state.error?.let { message ->
        AlertDialog(
            onDismissRequest = vm::dismissError,
            confirmButton = { TextButton(onClick = vm::dismissError) { Text("Dismiss") } },
            title = { Text("Notice") },
            text = { Text(message) },
        )
    }

    state.safetyNumber?.let { (peer, number) ->
        AlertDialog(
            onDismissRequest = vm::clearSafetyNumber,
            confirmButton = { TextButton(onClick = vm::clearSafetyNumber) { Text("Close") } },
            dismissButton = {
                TextButton(onClick = { vm.markVerified(peer); vm.clearSafetyNumber() }) {
                    Text("Mark verified")
                }
            },
            title = { Text("Safety number — $peer") },
            text = { Text("Compare this out of band with $peer:\n\n$number") },
        )
    }

    state.status?.let { message ->
        AlertDialog(
            onDismissRequest = vm::clearStatus,
            confirmButton = { TextButton(onClick = vm::clearStatus) { Text("OK") } },
            title = { Text("Status") },
            text = { Text(message) },
        )
    }
}

@Composable
private fun LoadingScreen() {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) { CircularProgressIndicator() }
}

// ---- Setup --------------------------------------------------------------

@Composable
private fun SetupScreen(state: UiState, vm: MessengerViewModel) {
    var dir by remember { mutableStateOf(state.dirUrl) }
    var queue by remember { mutableStateOf(state.queueUrl) }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Server setup", style = MaterialTheme.typography.headlineSmall)
        OutlinedTextField(
            value = dir, onValueChange = { dir = it },
            label = { Text("Directory URL") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = queue, onValueChange = { queue = it },
            label = { Text("Queue URL") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = { vm.saveSetup(dir, queue) }, modifier = Modifier.fillMaxWidth()) {
            Text("Continue")
        }
    }
}

// ---- Onboarding ---------------------------------------------------------

@Composable
private fun OnboardingScreen(state: UiState, vm: MessengerViewModel) {
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Create your account", style = MaterialTheme.typography.headlineSmall)
        when (state.onboarding.stage) {
            OnboardingStage.DETAILS -> {
                OutlinedTextField(
                    value = state.onboarding.handle,
                    onValueChange = { vm.updateOnboarding(handle = it) },
                    label = { Text("Handle") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = state.onboarding.email,
                    onValueChange = { vm.updateOnboarding(email = it) },
                    label = { Text("Email") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { vm.startEmailVerification() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Send verification code") }
            }
            OnboardingStage.CODE -> {
                var code by remember { mutableStateOf("") }
                Text("Enter the code sent to ${state.onboarding.email}.")
                state.onboarding.devCode?.let {
                    Text(
                        "Dev mode code: $it",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                OutlinedTextField(
                    value = code, onValueChange = { code = it },
                    label = { Text("Verification code") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { vm.confirmAndRegister(code) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Confirm & register") }
            }
        }
    }
}

// ---- Conversations ------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConversationsScreen(state: UiState, vm: MessengerViewModel) {
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Conversations") },
            actions = {
                TextButton(onClick = vm::syncNow) { Text("Sync") }
                TextButton(onClick = vm::openGroups) { Text("Groups") }
                TextButton(onClick = vm::openContacts) { Text("Contacts") }
                TextButton(onClick = vm::openSettings) { Text("Settings") }
            },
        )
        if (state.conversations.isEmpty()) {
            Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) { Text("No conversations yet.") }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(state.conversations, key = { it.peer }) { convo ->
                    ConversationRow(convo) { vm.openThread(convo.peer) }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun ConversationRow(convo: Conversation, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(16.dp),
    ) {
        val title = convo.displayName.ifEmpty { convo.peer }
        Text(title, style = MaterialTheme.typography.titleMedium)
        Text(
            convo.lastPreview,
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

// ---- Thread -------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ThreadScreen(state: UiState, vm: MessengerViewModel) {
    var draft by remember { mutableStateOf("") }
    // A document picker for file attachments; hands the chosen Uri to the VM,
    // which reads its bytes off the main thread and calls sendFile.
    val attachPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> uri?.let { vm.sendFile(it) } }

    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text(state.openPeer ?: "Thread") },
            navigationIcon = {
                TextButton(onClick = vm::back) { Text("Back") }
            },
            actions = {
                state.openPeer?.let { peer ->
                    TextButton(onClick = { vm.showSafetyNumber(peer) }) { Text("Verify") }
                }
            },
        )
        LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp)) {
            items(state.thread, key = { it.id }) { msg ->
                MessageRow(
                    msg = msg,
                    onReply = { vm.startReply(msg) },
                    onReact = { emoji -> vm.reactTo(msg.id, emoji) },
                    onDelete = { vm.deleteOwn(msg.id) },
                )
            }
        }
        HorizontalDivider()
        state.replyTo?.let { target ->
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Replying to: ${target.text.take(60)}",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                TextButton(onClick = vm::cancelReply) { Text("Cancel") }
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = { attachPicker.launch("*/*") }) { Text("Attach") }
            OutlinedTextField(
                value = draft, onValueChange = { draft = it },
                label = { Text("Message") },
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                vm.sendText(draft)
                draft = ""
            }) { Text("Send") }
        }
    }
}

@Composable
private fun MessageRow(
    msg: Message,
    onReply: () -> Unit,
    onReact: (String) -> Unit,
    onDelete: () -> Unit,
) {
    val align = if (msg.fromMe) Alignment.End else Alignment.Start
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalAlignment = align) {
        Text(msg.text, style = MaterialTheme.typography.bodyLarge)
        if (msg.fromMe) {
            Text(deliveryLabel(msg.delivery), style = MaterialTheme.typography.labelSmall)
        }
        // Per-message affordances: reply, quick-react, and delete-own.
        Row(
            Modifier.horizontalScroll(rememberScrollState()),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onReply) { Text("Reply") }
            for (emoji in QUICK_REACTS) {
                TextButton(onClick = { onReact(emoji) }) { Text(emoji) }
            }
            if (msg.fromMe) {
                TextButton(onClick = onDelete) { Text("Delete") }
            }
        }
    }
}

private fun deliveryLabel(state: DeliveryState): String = when (state) {
    DeliveryState.SENT -> "Sent"
    DeliveryState.QUEUED -> "Queued…"
    DeliveryState.DELIVERED -> "Delivered"
    DeliveryState.FAILED -> "Failed"
}

// ---- Contacts -----------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactsScreen(state: UiState, vm: MessengerViewModel) {
    var nickname by remember { mutableStateOf("") }
    var handle by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Contacts") },
            navigationIcon = {
                TextButton(onClick = vm::back) { Text("Back") }
            },
        )
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = nickname, onValueChange = { nickname = it },
                label = { Text("Nickname") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = handle, onValueChange = { handle = it },
                label = { Text("Handle") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = {
                vm.addContact(nickname, handle)
                nickname = ""; handle = ""
            }, modifier = Modifier.fillMaxWidth()) { Text("Add contact") }
        }
        HorizontalDivider()
        LazyColumn(Modifier.fillMaxSize()) {
            items(state.contacts, key = { it.handle }) { contact ->
                ContactRow(contact) { vm.showSafetyNumber(contact.handle) }
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun ContactRow(contact: Contact, onVerify: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(contact.nickname, style = MaterialTheme.typography.titleMedium)
            Text(
                "${contact.handle} · ${contact.trust.name.lowercase()}",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        TextButton(onClick = onVerify) { Text("Safety number") }
    }
}

// ---- Groups -------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GroupsScreen(state: UiState, vm: MessengerViewModel) {
    var name by remember { mutableStateOf("") }
    var members by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Groups") },
            navigationIcon = { TextButton(onClick = vm::back) { Text("Back") } },
            actions = { TextButton(onClick = vm::syncNow) { Text("Sync") } },
        )
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = name, onValueChange = { name = it },
                label = { Text("Group name") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = members, onValueChange = { members = it },
                label = { Text("Members (comma-separated handles)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = {
                vm.createGroup(name, members)
                name = ""; members = ""
            }, modifier = Modifier.fillMaxWidth()) { Text("Create group") }
        }
        HorizontalDivider()
        if (state.groups.isEmpty()) {
            Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) { Text("No groups yet.") }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(state.groups, key = { it.id }) { group ->
                    GroupRow(group) { vm.openGroupThread(group.id, group.name.ifEmpty { group.id }) }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun GroupRow(group: Group, onClick: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(16.dp),
    ) {
        Text(group.name.ifEmpty { group.id }, style = MaterialTheme.typography.titleMedium)
        val count = group.members.size
        Text(
            "$count member${if (count == 1) "" else "s"}",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GroupThreadScreen(state: UiState, vm: MessengerViewModel) {
    var draft by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("${state.openGroupName} (group)") },
            navigationIcon = { TextButton(onClick = vm::back) { Text("Back") } },
            actions = { TextButton(onClick = vm::leaveGroup) { Text("Leave") } },
        )
        LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp)) {
            items(state.groupThread, key = { it.id }) { msg -> GroupMessageRow(msg) }
        }
        HorizontalDivider()
        Row(
            Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = draft, onValueChange = { draft = it },
                label = { Text("Message") },
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                vm.sendGroupText(draft)
                draft = ""
            }) { Text("Send") }
        }
    }
}

@Composable
private fun GroupMessageRow(msg: Message) {
    val align = if (msg.fromMe) Alignment.End else Alignment.Start
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalAlignment = align) {
        if (!msg.fromMe) {
            Text(msg.sender, style = MaterialTheme.typography.labelSmall)
        }
        Text(msg.text, style = MaterialTheme.typography.bodyLarge)
        if (msg.fromMe) {
            Text(deliveryLabel(msg.delivery), style = MaterialTheme.typography.labelSmall)
        }
    }
}

// ---- Pairing (link a device) --------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PairingScreen(state: UiState, vm: MessengerViewModel) {
    var offer by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Link a device") },
            navigationIcon = { TextButton(onClick = vm::back) { Text("Back") } },
        )
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("On the NEW device", style = MaterialTheme.typography.titleMedium)
            Text(
                "Mint a one-time offer, show it to an already-linked device, then poll " +
                    "until it approves.",
                style = MaterialTheme.typography.bodySmall,
            )
            Button(onClick = vm::makePairOffer, modifier = Modifier.fillMaxWidth()) {
                Text("Create pairing offer")
            }
            state.pairOffer?.let { code ->
                OutlinedTextField(
                    value = code, onValueChange = {}, readOnly = true,
                    label = { Text("Your pairing offer") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            Button(onClick = vm::pollPairing, modifier = Modifier.fillMaxWidth()) {
                Text("Poll for approval")
            }
            HorizontalDivider()
            Text("On an EXISTING device", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = offer, onValueChange = { offer = it },
                label = { Text("Paste the new device's offer") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = {
                vm.approveDevice(offer)
                offer = ""
            }, modifier = Modifier.fillMaxWidth()) { Text("Approve device") }
        }
    }
}

// ---- Settings -----------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsScreen(state: UiState, vm: MessengerViewModel) {
    var cardToVerify by remember { mutableStateOf("") }
    var pushEndpoint by remember { mutableStateOf("") }
    val exportPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri -> uri?.let { vm.exportBackup(it) } }
    val importPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> uri?.let { vm.importBackup(it) } }

    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Settings") },
            navigationIcon = { TextButton(onClick = vm::back) { Text("Back") } },
        )
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Contact card (verification).
            Text("My contact card", style = MaterialTheme.typography.titleMedium)
            Button(onClick = vm::loadContactCard, modifier = Modifier.fillMaxWidth()) {
                Text("Show my card")
            }
            state.myCard?.let { card ->
                OutlinedTextField(
                    value = card, onValueChange = {}, readOnly = true,
                    label = { Text("Your card (share out of band)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            OutlinedTextField(
                value = cardToVerify, onValueChange = { cardToVerify = it },
                label = { Text("Verify a pasted card") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = {
                vm.verifyCard(cardToVerify)
                cardToVerify = ""
            }, modifier = Modifier.fillMaxWidth()) { Text("Verify card") }

            HorizontalDivider()

            // Device linking.
            Text("Devices", style = MaterialTheme.typography.titleMedium)
            Button(onClick = vm::openPairing, modifier = Modifier.fillMaxWidth()) {
                Text("Link a device")
            }

            HorizontalDivider()

            // Backup.
            Text("Backup", style = MaterialTheme.typography.titleMedium)
            Button(
                onClick = { exportPicker.launch("mycellium-backup.mycbak") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Export backup") }
            Button(
                onClick = { importPicker.launch("*/*") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Import backup") }

            HorizontalDivider()

            // Push notifications.
            Text("Notifications", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = pushEndpoint, onValueChange = { pushEndpoint = it },
                label = { Text("UnifiedPush endpoint URL") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = {
                vm.registerUnifiedPush(pushEndpoint)
            }, modifier = Modifier.fillMaxWidth()) { Text("Register endpoint") }
        }
    }
}
