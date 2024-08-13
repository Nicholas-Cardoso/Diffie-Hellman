package algorithm.com

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun main() {
    val p = BigInteger("25")
    val g = BigInteger("5")

    val random = SecureRandom()
    val firstPrivateKey = BigInteger(p.bitLength() - 1, random)
    val secondPrivateKey = BigInteger(p.bitLength() - 1, random)

    val firstPublicKey = g.modPow(firstPrivateKey, p)
    val secondPublicKey = g.modPow(secondPrivateKey, p)

    val firstSharedSecret = secondPublicKey.modPow(firstPrivateKey, p)
    val secondSharedSecret = firstPublicKey.modPow(secondPrivateKey, p)

    require(firstSharedSecret == secondSharedSecret) { "Chaves secretas compartilhadas são diferentes!" }
    val sharedSecret = firstSharedSecret.toByteArray()

    val aesKey = deriveAESKey(sharedSecret)

    val message = "Olá"

    val encryptedMessage = encrypt(message, aesKey)
    println("Mensagem encriptada: $encryptedMessage")

    val decryptedMessage = decrypt(encryptedMessage, aesKey)
    println("Mensagem desencriptada: $decryptedMessage")
}

fun deriveAESKey(sharedSecret: ByteArray): SecretKey {
    val sha256 = MessageDigest.getInstance("SHA-256")
    val keyBytes = sha256.digest(sharedSecret).copyOf(16)
    return SecretKeySpec(keyBytes, "AES")
}

fun encrypt(data: String, secretKey: SecretKey): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    val encrypted = cipher.doFinal(data.toByteArray())
    return Base64.getEncoder().encodeToString(iv + encrypted)
}

fun decrypt(encryptedData: String, secretKey: SecretKey): String {
    val decodedData = Base64.getDecoder().decode(encryptedData)
    val iv = decodedData.copyOfRange(0, 16)
    val encrypted = decodedData.copyOfRange(16, decodedData.size)
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
    val decrypted = cipher.doFinal(encrypted)
    return String(decrypted)
}