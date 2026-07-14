@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package eu.mycellium.android.ui

import android.content.Intent
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.ChatBubbleOutline
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Groups
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.PersonOutline
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import eu.mycellium.android.MessengerUiState
import eu.mycellium.android.MessengerViewModel
import eu.mycellium.android.ui.theme.Border
import eu.mycellium.android.ui.theme.Canvas
import eu.mycellium.android.ui.theme.Danger
import eu.mycellium.android.ui.theme.Moss
import eu.mycellium.android.ui.theme.Muted
import eu.mycellium.android.ui.theme.Sidebar
import eu.mycellium.android.ui.theme.Spore
import eu.mycellium.android.ui.theme.SurfaceRaised
import eu.mycellium.android.ui.theme.Text as TextColor
import java.text.DateFormat
import java.util.Date
import uniffi.mycellium_mobile.ClientState
import uniffi.mycellium_mobile.ContactInfo
import uniffi.mycellium_mobile.ContactSecurityInfo
import uniffi.mycellium_mobile.ConversationInfo
import uniffi.mycellium_mobile.MessageInfo

private enum class Tab { Messages, People, You }

@Composable
fun MycelliumRoot(model: MessengerViewModel) {
    val state by model.state.collectAsStateWithLifecycle()
    val snackbars = remember { SnackbarHostState() }
    LaunchedEffect(state.error, state.notice) {
        val message = state.error ?: state.notice
        if (message != null && state.initialized) {
            snackbars.showSnackbar(message)
            model.clearMessage()
        }
    }

    Box(Modifier.fillMaxSize().background(Canvas)) {
        when {
            !state.initialized -> LaunchScreen()
            state.clientState == ClientState.READY -> {
                if (state.selectedUserId != null) {
                    ConversationScreen(state, model)
                } else {
                    HomeScreen(state, model, snackbars)
                }
            }
            else -> AccountScreen(state, model, snackbars)
        }
    }
}

@Composable
private fun LaunchScreen() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            NodeMark(72.dp)
            Spacer(Modifier.height(24.dp))
            CircularProgressIndicator(color = Moss, strokeWidth = 2.dp, modifier = Modifier.size(24.dp))
        }
    }
}

@Composable
private fun AccountScreen(
    state: MessengerUiState,
    model: MessengerViewModel,
    snackbars: SnackbarHostState,
) {
    var email by rememberSaveable { mutableStateOf("") }
    var code by rememberSaveable { mutableStateOf("") }
    var displayName by rememberSaveable { mutableStateOf("") }
    var handle by rememberSaveable { mutableStateOf("") }

    Scaffold(
        containerColor = Canvas,
        snackbarHost = { SnackbarHost(snackbars) },
        contentWindowInsets = WindowInsets(0),
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .statusBarsPadding()
                .navigationBarsPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 28.dp, vertical = 30.dp),
        ) {
            NodeMark(58.dp)
            Spacer(Modifier.height(42.dp))
            AnimatedContent(state.clientState, label = "account-state") { clientState ->
                when (clientState) {
                    ClientState.NEEDS_PROFILE -> {
                        Column {
                            Text("What should people call you?", style = MaterialTheme.typography.headlineMedium)
                            Spacer(Modifier.height(10.dp))
                            Text(
                                "Your name is shown in conversations. Your handle is a short, non-unique label.",
                                color = Muted,
                            )
                            Spacer(Modifier.height(32.dp))
                            OutlinedTextField(
                                value = displayName,
                                onValueChange = { displayName = it },
                                label = { Text("Display name") },
                                singleLine = true,
                                enabled = !state.busy,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Spacer(Modifier.height(12.dp))
                            OutlinedTextField(
                                value = handle,
                                onValueChange = { value ->
                                    handle = value.lowercase().filter {
                                        it.isLetterOrDigit() || it == '_'
                                    }.take(32)
                                },
                                label = { Text("Handle") },
                                supportingText = { Text("Lowercase letters, numbers, and underscores") },
                                singleLine = true,
                                enabled = !state.busy,
                                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                                    imeAction = ImeAction.Done,
                                ),
                                keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                                    onDone = { model.saveProfile(handle, displayName) },
                                ),
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Spacer(Modifier.height(20.dp))
                            PrimaryButton("Continue", state.busy) {
                                model.saveProfile(handle, displayName)
                            }
                        }
                    }
                    else -> {
                        Column {
                            if (clientState == ClientState.REPLACED) {
                                StatusCard(
                                    title = "This device was replaced",
                                    body = "Messages remain here, but sending is disabled. Log in again to make this device active.",
                                    accent = Spore,
                                )
                                Spacer(Modifier.height(28.dp))
                            }
                            Text(
                                if (state.loginRequested) "Enter your login code" else "Continue with email",
                                style = MaterialTheme.typography.headlineMedium,
                            )
                            Spacer(Modifier.height(10.dp))
                            Text(
                                if (state.loginRequested) {
                                    "We sent a one-time code to your email."
                                } else {
                                    "Your email opens your account on this device."
                                },
                                color = Muted,
                            )
                            Spacer(Modifier.height(32.dp))
                            if (!state.loginRequested) {
                                OutlinedTextField(
                                    value = email,
                                    onValueChange = { email = it },
                                    label = { Text("Email address") },
                                    singleLine = true,
                                    enabled = !state.busy,
                                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                                        keyboardType = KeyboardType.Email,
                                        imeAction = ImeAction.Send,
                                    ),
                                    keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                                        onSend = { model.requestLogin(email) },
                                    ),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(18.dp))
                                PrimaryButton("Email me a code", state.busy) { model.requestLogin(email) }
                            } else {
                                OutlinedTextField(
                                    value = code,
                                    onValueChange = { code = it.trim().take(128) },
                                    label = { Text("Login code") },
                                    singleLine = true,
                                    enabled = !state.busy,
                                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                                        imeAction = ImeAction.Done,
                                    ),
                                    keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                                        onDone = { model.confirmLogin(code) },
                                    ),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(18.dp))
                                PrimaryButton("Open my account", state.busy) { model.confirmLogin(code) }
                                TextButton(
                                    onClick = model::restartLogin,
                                    modifier = Modifier.align(Alignment.CenterHorizontally),
                                ) { Text("Use another email") }
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(48.dp))
            Text("PRIVATE BY STRUCTURE", style = MaterialTheme.typography.labelSmall, color = Moss)
        }
    }
}

@Composable
private fun HomeScreen(
    state: MessengerUiState,
    model: MessengerViewModel,
    snackbars: SnackbarHostState,
) {
    var tab by rememberSaveable { mutableStateOf(Tab.Messages) }
    var addPerson by rememberSaveable { mutableStateOf(false) }
    Scaffold(
        containerColor = Canvas,
        snackbarHost = { SnackbarHost(snackbars) },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(tab.name, style = MaterialTheme.typography.titleLarge)
                        if (tab == Tab.Messages && state.pendingCount > 0uL) {
                            Text("${state.pendingCount} pending", style = MaterialTheme.typography.labelSmall, color = Spore)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Canvas),
                modifier = Modifier.statusBarsPadding(),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = Sidebar, modifier = Modifier.navigationBarsPadding()) {
                NavigationBarItem(
                    selected = tab == Tab.Messages,
                    onClick = { tab = Tab.Messages },
                    icon = { Icon(Icons.Rounded.ChatBubbleOutline, null) },
                    label = { Text("Messages") },
                )
                NavigationBarItem(
                    selected = tab == Tab.People,
                    onClick = { tab = Tab.People },
                    icon = { Icon(Icons.Rounded.Groups, null) },
                    label = { Text("People") },
                )
                NavigationBarItem(
                    selected = tab == Tab.You,
                    onClick = { tab = Tab.You },
                    icon = { Icon(Icons.Rounded.PersonOutline, null) },
                    label = { Text("You") },
                )
            }
        },
        floatingActionButton = {
            if (tab == Tab.People) {
                FloatingActionButton(onClick = { addPerson = true }, containerColor = Moss) {
                    Icon(Icons.Rounded.Add, "Add person", tint = Canvas)
                }
            }
        },
    ) { padding ->
        AnimatedContent(tab, label = "home-tab", modifier = Modifier.padding(padding)) { current ->
            when (current) {
                Tab.Messages -> MessagesTab(state, model)
                Tab.People -> PeopleTab(state, model)
                Tab.You -> ProfileTab(state, model)
            }
        }
    }
    if (addPerson) {
        AddPersonDialog(
            busy = state.busy,
            onDismiss = { addPerson = false },
            onAdd = { card, nickname ->
                model.addContact(card, nickname)
                addPerson = false
            },
        )
    }
    state.security?.let { security ->
        SecurityDialog(
            security = security,
            busy = state.busy,
            onDismiss = model::dismissSecurity,
            onVerify = { model.verifyContact(security.userId) },
            onAccept = { model.acceptIdentityChange(security.userId) },
            onBlockedChange = { model.setContactBlocked(security.userId, it) },
        )
    }
}

@Composable
private fun MessagesTab(state: MessengerUiState, model: MessengerViewModel) {
    if (state.conversations.isEmpty()) {
        EmptyState(
            icon = { Icon(Icons.Rounded.ChatBubbleOutline, null, tint = Moss, modifier = Modifier.size(34.dp)) },
            title = "No conversations yet",
            body = "Add someone in People, then open their conversation.",
        )
        return
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp)) {
        items(state.conversations, key = { it.userId }) { conversation ->
            ConversationRow(conversation) {
                model.openConversation(conversation.userId, conversation.displayName)
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun ConversationRow(conversation: ConversationInfo, onClick: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Avatar(conversation.displayName)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        conversation.displayName,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Text(time(conversation.timestamp), style = MaterialTheme.typography.labelSmall, color = Muted)
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    (if (conversation.fromMe) "You: " else "") + conversation.preview,
                    color = Muted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun PeopleTab(state: MessengerUiState, model: MessengerViewModel) {
    if (state.contacts.isEmpty()) {
        EmptyState(
            icon = { Icon(Icons.Rounded.Groups, null, tint = Moss, modifier = Modifier.size(34.dp)) },
            title = "Your people appear here",
            body = "Add a connection card shared by someone you know.",
        )
        return
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp)) {
        items(state.contacts, key = { it.userId }) { contact ->
            ContactRow(contact, model)
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun ContactRow(contact: ContactInfo, model: MessengerViewModel) {
    Surface(color = MaterialTheme.colorScheme.surface, shape = RoundedCornerShape(16.dp)) {
        Row(
            Modifier.fillMaxWidth().clickable {
                model.openConversation(contact.userId, contact.nickname)
            }.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Avatar(contact.nickname)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(contact.nickname, style = MaterialTheme.typography.titleMedium)
                Text("@${contact.handle}", color = Muted, style = MaterialTheme.typography.bodyMedium)
            }
            IconButton(onClick = { model.showSecurity(contact.userId) }) {
                Icon(
                    Icons.Rounded.Security,
                    if (contact.verified) "Verified identity" else "Review identity",
                    tint = if (contact.verified) Moss else Muted,
                )
            }
        }
    }
}

@Composable
private fun ProfileTab(state: MessengerUiState, model: MessengerViewModel) {
    val profile = state.profile ?: return
    var editing by rememberSaveable(profile.userId) { mutableStateOf(false) }
    var displayName by rememberSaveable(profile.userId, profile.displayName) {
        mutableStateOf(profile.displayName)
    }
    var handle by rememberSaveable(profile.userId, profile.handle) {
        mutableStateOf(profile.handle)
    }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            NodeMark(52.dp)
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(profile.displayName, style = MaterialTheme.typography.titleLarge)
                Text("@${profile.handle}", color = Muted)
            }
            TextButton(onClick = { editing = !editing }) {
                Text(if (editing) "Cancel" else "Edit")
            }
        }
        AnimatedVisibility(editing) {
            Column(Modifier.padding(top = 18.dp)) {
                OutlinedTextField(
                    value = displayName,
                    onValueChange = { displayName = it.take(128) },
                    label = { Text("Display name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = handle,
                    onValueChange = { value ->
                        handle = value.lowercase().filter {
                            it.isLetterOrDigit() || it == '_'
                        }.take(64)
                    },
                    label = { Text("Handle") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = {
                        model.saveProfile(handle, displayName)
                        editing = false
                    },
                    enabled = !state.busy && handle.isNotBlank() && displayName.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Save profile")
                }
            }
        }
        Spacer(Modifier.height(28.dp))
        Text("YOUR CONNECTION CARD", style = MaterialTheme.typography.labelSmall, color = Moss)
        Spacer(Modifier.height(10.dp))
        Surface(color = MaterialTheme.colorScheme.surface, shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(18.dp)) {
                Text(
                    "Share this card with someone so they can add the exact identity—not just your handle.",
                    color = Muted,
                )
                Spacer(Modifier.height(14.dp))
                Text(
                    profile.connectionCard,
                    style = MaterialTheme.typography.labelSmall,
                    color = TextColor,
                    maxLines = 5,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedButton(
                        onClick = { clipboard.setText(AnnotatedString(profile.connectionCard)) },
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Rounded.ContentCopy, null)
                        Spacer(Modifier.width(8.dp))
                        Text("Copy")
                    }
                    Button(
                        onClick = {
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, profile.connectionCard)
                            }
                            context.startActivity(Intent.createChooser(intent, "Share connection card"))
                        },
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Rounded.Share, null)
                        Spacer(Modifier.width(8.dp))
                        Text("Share")
                    }
                }
            }
        }
        Spacer(Modifier.height(24.dp))
        StatusCard(
            title = if (state.pendingCount == 0uL) "Nothing pending" else "${state.pendingCount} pending",
            body = if (state.pendingCount == 0uL) {
                "Messages delivered directly have left this device."
            } else {
                "These messages remain encrypted on this device until a direct connection exists."
            },
            accent = if (state.pendingCount == 0uL) Moss else Spore,
        )
        AnimatedVisibility(state.pendingCount > 0uL) {
            OutlinedButton(
                onClick = model::retryPending,
                enabled = !state.busy,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            ) {
                Icon(Icons.Rounded.Refresh, null)
                Spacer(Modifier.width(8.dp))
                Text("Try now")
            }
        }
        Spacer(Modifier.height(28.dp))
        Text("USER ID", style = MaterialTheme.typography.labelSmall, color = Muted)
        Text(profile.userId, style = MaterialTheme.typography.labelSmall, color = TextColor)
    }
}

@Composable
private fun ConversationScreen(state: MessengerUiState, model: MessengerViewModel) {
    var draft by rememberSaveable(state.selectedUserId) { mutableStateOf("") }
    val listState = rememberLazyListState()
    LaunchedEffect(state.messages.size) {
        if (state.messages.isNotEmpty()) listState.animateScrollToItem(state.messages.lastIndex)
    }
    Scaffold(
        containerColor = Canvas,
        topBar = {
            TopAppBar(
                title = { Text(state.selectedTitle, style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    IconButton(onClick = model::closeConversation) {
                        Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Canvas),
                modifier = Modifier.statusBarsPadding(),
            )
        },
        bottomBar = {
            Row(
                Modifier.fillMaxWidth().background(Sidebar).navigationBarsPadding().imePadding().padding(10.dp),
                verticalAlignment = Alignment.Bottom,
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    placeholder = { Text("Message") },
                    maxLines = 5,
                    enabled = !state.busy,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = androidx.compose.foundation.text.KeyboardActions(
                        onSend = {
                            if (draft.isNotBlank()) {
                                model.sendMessage(draft)
                                draft = ""
                            }
                        },
                    ),
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                IconButton(
                    onClick = {
                        if (draft.isNotBlank()) {
                            model.sendMessage(draft)
                            draft = ""
                        }
                    },
                    enabled = draft.isNotBlank() && !state.busy,
                    modifier = Modifier.size(52.dp).clip(CircleShape).background(Moss),
                ) {
                    Icon(Icons.AutoMirrored.Rounded.Send, "Send", tint = Canvas)
                }
            }
        },
    ) { padding ->
        if (state.messages.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("Messages stay on your devices.", color = Muted)
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(state.messages, key = { it.id.ifEmpty { "${it.timestamp}-${it.text.hashCode()}" } }) { message ->
                    MessageBubble(message)
                }
            }
        }
    }
}

@Composable
private fun MessageBubble(message: MessageInfo) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (message.fromMe) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            color = if (message.fromMe) MaterialTheme.colorScheme.primaryContainer else SurfaceRaised,
            shape = RoundedCornerShape(
                topStart = 18.dp,
                topEnd = 18.dp,
                bottomStart = if (message.fromMe) 18.dp else 4.dp,
                bottomEnd = if (message.fromMe) 4.dp else 18.dp,
            ),
            modifier = Modifier.fillMaxWidth(0.82f),
        ) {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                Text(message.text, color = TextColor)
                Spacer(Modifier.height(4.dp))
                Text(time(message.timestamp), style = MaterialTheme.typography.labelSmall, color = Muted)
            }
        }
    }
}

@Composable
private fun AddPersonDialog(busy: Boolean, onDismiss: () -> Unit, onAdd: (String, String) -> Unit) {
    var nickname by rememberSaveable { mutableStateOf("") }
    var card by rememberSaveable { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add someone") },
        text = {
            Column {
                Text("Paste the connection card they shared with you.", color = Muted)
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = nickname,
                    onValueChange = { nickname = it },
                    label = { Text("Name on this device (optional)") },
                    singleLine = true,
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = card,
                    onValueChange = { card = it },
                    label = { Text("Connection card") },
                    minLines = 4,
                    maxLines = 8,
                )
            }
        },
        confirmButton = {
            Button(onClick = { onAdd(card, nickname) }, enabled = card.isNotBlank() && !busy) {
                Text("Add person")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun SecurityDialog(
    security: ContactSecurityInfo,
    busy: Boolean,
    onDismiss: () -> Unit,
    onVerify: () -> Unit,
    onAccept: () -> Unit,
    onBlockedChange: (Boolean) -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Rounded.Security, null, tint = if (security.identityChanged) Danger else Moss) },
        title = { Text(if (security.identityChanged) "Identity changed" else security.trust) },
        text = {
            Column {
                Text(
                    if (security.identityChanged) {
                        "Do not accept this change until you verify the number with this person another way."
                    } else {
                        "Compare this number with the person using another trusted channel."
                    },
                    color = Muted,
                )
                Spacer(Modifier.height(16.dp))
                Text("SAFETY NUMBER", style = MaterialTheme.typography.labelSmall, color = Moss)
                Spacer(Modifier.height(6.dp))
                Text(security.safetyNumber, style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.height(16.dp))
                OutlinedButton(
                    onClick = { onBlockedChange(!security.blocked) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (security.blocked) "Unblock this person" else "Block this person")
                }
            }
        },
        confirmButton = {
            Button(
                onClick = if (security.identityChanged) onAccept else onVerify,
                enabled = !busy,
                colors = if (security.identityChanged) {
                    ButtonDefaults.buttonColors(containerColor = Danger, contentColor = Canvas)
                } else {
                    ButtonDefaults.buttonColors()
                },
            ) {
                Text(if (security.identityChanged) "Accept new identity" else "Numbers match")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}

@Composable
private fun PrimaryButton(label: String, busy: Boolean, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = !busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(20.dp), color = Canvas, strokeWidth = 2.dp)
        } else {
            Text(label)
        }
    }
}

@Composable
private fun StatusCard(title: String, body: String, accent: Color) {
    Surface(color = MaterialTheme.colorScheme.surface, shape = RoundedCornerShape(16.dp)) {
        Row(Modifier.padding(16.dp)) {
            Box(Modifier.size(10.dp).clip(CircleShape).background(accent))
            Spacer(Modifier.width(12.dp))
            Column {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(3.dp))
                Text(body, color = Muted, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun EmptyState(icon: @Composable () -> Unit, title: String, body: String) {
    Box(Modifier.fillMaxSize().padding(40.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            icon()
            Spacer(Modifier.height(18.dp))
            Text(title, style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(8.dp))
            Text(body, color = Muted, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun Avatar(name: String) {
    Box(
        Modifier.size(44.dp).clip(CircleShape).background(SurfaceRaised),
        contentAlignment = Alignment.Center,
    ) {
        Text(name.trim().take(1).uppercase().ifEmpty { "?" }, color = Moss, style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun NodeMark(size: androidx.compose.ui.unit.Dp) {
    Canvas(Modifier.size(size)) {
        val radius = this.size.minDimension * 0.09f
        val left = Offset(this.size.width * 0.18f, this.size.height * 0.5f)
        val top = Offset(this.size.width * 0.5f, this.size.height * 0.2f)
        val right = Offset(this.size.width * 0.82f, this.size.height * 0.5f)
        val bottom = Offset(this.size.width * 0.5f, this.size.height * 0.8f)
        val line = Stroke(width = this.size.minDimension * 0.035f, cap = StrokeCap.Round)
        drawLine(Moss, left, top, strokeWidth = line.width)
        drawLine(Moss, top, right, strokeWidth = line.width)
        drawLine(Moss, right, bottom, strokeWidth = line.width)
        drawLine(Moss, bottom, left, strokeWidth = line.width)
        drawCircle(Moss, radius, left)
        drawCircle(Moss, radius, top)
        drawCircle(Spore, radius, right)
        drawCircle(Moss, radius, bottom)
    }
}

private fun time(timestamp: ULong): String = DateFormat.getTimeInstance(DateFormat.SHORT)
    .format(Date(timestamp.toLong() * 1_000L))
