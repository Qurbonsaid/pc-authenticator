package com.kuzatuvchi.pcauthenticator

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow
import kotlinx.coroutines.delay

class MainActivity : FragmentActivity() {

    private lateinit var prefs: android.content.SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        generateKeyIfNotExists()
        prefs = getSharedPreferences("secure_prefs", MODE_PRIVATE)

        setContent {
            var userPin by remember {
                mutableStateOf(
                    loadDecryptedPin()?.takeIf { it.length == 6 && it.all(Char::isDigit) }
                )
            }
            var authenticated by remember { mutableStateOf(false) }
            var setupPin by remember { mutableStateOf("") }
            var confirmPin by remember { mutableStateOf("") }

            when {
                userPin == null && setupPin.isEmpty() -> {
                    PinSetupScreen { entered ->
                        if (entered.length == 6 && entered.all(Char::isDigit)) {
                            setupPin = entered
                        } else {
                            Toast.makeText(this, "PIN must be 6 digits", Toast.LENGTH_SHORT).show()
                        }
                    }
                }

                userPin == null && confirmPin.isEmpty() -> {
                    PinConfirmScreen(setupPin) { confirmed ->
                        if (confirmed == setupPin) {
                            val (iv, encrypted) = encryptData(confirmed)
                            prefs.edit {
                                putString("user_pin_iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                                putString("user_pin_enc", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                            }
                            userPin = confirmed
                        } else {
                            Toast.makeText(this, "PINs do not match", Toast.LENGTH_SHORT).show()
                            setupPin = ""
                        }
                    }
                }

                !authenticated -> {
                    PinLoginScreen(
                        onPinEntered = { entered ->
                            if (entered == userPin) {
                                authenticated = true
                            } else {
                                Toast.makeText(this, "Wrong PIN", Toast.LENGTH_SHORT).show()
                            }
                        },
                        onAuthSuccess = { authenticated = true },
                    )
                }

                else -> {
                    TOTPDisplay(userPin!!)
                }
            }
        }
    }

    private fun loadDecryptedPin(): String? {
        val ivString = prefs.getString("user_pin_iv", null) ?: return null
        val encString = prefs.getString("user_pin_enc", null) ?: return null
        return try {
            decryptData(
                Base64.decode(encString, Base64.NO_WRAP),
                Base64.decode(ivString, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private fun generateKeyIfNotExists() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!keyStore.containsAlias("auth_key")) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                "auth_key",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        }
    }

    private fun encryptData(plainText: String): Pair<ByteArray, ByteArray> {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val secretKey = (keyStore.getEntry("auth_key", null) as KeyStore.SecretKeyEntry).secretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.iv to cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
    }

    private fun decryptData(cipherText: ByteArray, iv: ByteArray): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val secretKey = (keyStore.getEntry("auth_key", null) as KeyStore.SecretKeyEntry).secretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(cipherText), Charsets.UTF_8)
    }

    @Composable
    fun PinLoginScreen(onPinEntered: (String) -> Unit, onAuthSuccess: () -> Unit) {
        val context = LocalContext.current
        LaunchedEffect(Unit) {
            val executor = ContextCompat.getMainExecutor(context)
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate")
                .setSubtitle("Use biometric or enter PIN")
                .setNegativeButtonText("Enter PIN")
                .build()

            val biometricPrompt = BiometricPrompt(
                context as FragmentActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        onAuthSuccess()
                    }

                    override fun onAuthenticationFailed() {
                        Toast.makeText(context, "Biometric failed", Toast.LENGTH_SHORT).show()
                    }
                })

            biometricPrompt.authenticate(promptInfo)
        }
        var pin by remember { mutableStateOf("") }
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text("Enter your 6-digit PIN", fontSize = 20.sp)
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = pin,
                onValueChange = {
                    if (it.length <= 6 && it.all(Char::isDigit)) pin = it
                },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true
            )
            Spacer(Modifier.height(16.dp))
            Button(onClick = { onPinEntered(pin) }, enabled = pin.length == 6) {
                Text("Login")
            }
        }
    }

    @Composable
    fun PinConfirmScreen(originalPin: String, onConfirmed: (String) -> Unit) {
        var pin by remember { mutableStateOf("") }
        var errorMessage by remember { mutableStateOf("") }

        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text("Confirm your 6-digit PIN", fontSize = 20.sp)
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = pin,
                onValueChange = {
                    if (it.length <= 6 && it.all(Char::isDigit)) pin = it
                },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true
            )
            Spacer(Modifier.height(16.dp))

            if (errorMessage.isNotEmpty()) {
                Text(text = errorMessage, color = Color.Red, fontSize = 14.sp)
                Spacer(Modifier.height(8.dp))
            }

            Button(onClick = {
                if (pin == originalPin) {
                    onConfirmed(pin)
                } else {
                    errorMessage = "PIN does not match the original PIN."
                }
            }, enabled = pin.length == 6) {
                Text("Confirm")
            }
        }
    }


    @Composable
    fun PinSetupScreen(onPinSet: (String) -> Unit) {
        var pin by remember { mutableStateOf("") }
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text("Set a 6-digit PIN", fontSize = 20.sp)
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = pin,
                onValueChange = {
                    if (it.length <= 6 && it.all(Char::isDigit)) pin = it
                },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true
            )
            Spacer(Modifier.height(16.dp))
            Button(onClick = { onPinSet(pin) }, enabled = pin.length == 6) {
                Text("Save PIN")
            }
        }
    }

    @Composable
    fun TOTPDisplay(pin: String) {
        val context = LocalContext.current
        var otp by remember { mutableStateOf("------") }
        var progress by remember { mutableFloatStateOf(1f) }
        val clipboard = context.getSystemService(CLIPBOARD_SERVICE) as ClipboardManager

        LaunchedEffect(Unit) {
            while (true) {
                val currentTime = System.currentTimeMillis()
                otp = generateTOTPFromPin(pin.toByteArray(), currentTime)

                val start = currentTime
                val end = start + 30_000

                while (System.currentTimeMillis() < end) {
                    val elapsed = System.currentTimeMillis() - start
                    progress = 1f - (elapsed / 30_000f)
                    delay(1000)
                }
            }
        }

        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(modifier = Modifier.clickable {
                    clipboard.setPrimaryClip(ClipData.newPlainText("TOTP", otp))
                    Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
                }, text = otp, fontSize = 48.sp)
                Spacer(modifier = Modifier.height(16.dp))
                TimerIndicator(progress)
            }
        }
    }

    @Composable
    fun TimerIndicator(progress: Float) {
        CircularProgressIndicator(
            progress = { progress },
            modifier = Modifier.size(64.dp),
            color = MaterialTheme.colorScheme.primary,
            strokeWidth = 8.dp,
            trackColor = MaterialTheme.colorScheme.surface,
            strokeCap = StrokeCap.Round,
        )
    }

    fun generateTOTPFromPin(secret: ByteArray, time: Long, digits: Int = 6): String {
        val buffer = ByteBuffer.allocate(8).putLong(time / 30_000).array()
        val key = SecretKeySpec(secret, "HmacSHA1")
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(key)
        val hash = mac.doFinal(buffer)
        val offset = hash[hash.size - 1].toInt() and 0xF
        val binary = (hash[offset].toInt() and 0x7F shl 24) or
                (hash[offset + 1].toInt() and 0xFF shl 16) or
                (hash[offset + 2].toInt() and 0xFF shl 8) or
                (hash[offset + 3].toInt() and 0xFF)
        return (binary % 10.0.pow(digits).toInt()).toString().padStart(digits, '0')
    }
}
