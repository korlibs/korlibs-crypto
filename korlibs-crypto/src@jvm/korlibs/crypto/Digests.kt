package korlibs.crypto

import java.security.MessageDigest

fun MessageDigest.asHasher(): HasherFactory = MessageDigestHasherFactory(this)

fun ByteArray.hash(algo: MessageDigest): Hash = algo.asHasher().digest(this)

internal class MessageDigestHasher(
    val md: MessageDigest,
) : NonCoreHasher(0, md.digestLength, md.algorithm) {
    override fun reset(): Hasher {
        md.reset()
        return this
    }

    override fun update(data: ByteArray, offset: Int, count: Int): Hasher {
        md.update(data, offset, count)
        return this
    }

    override fun digestOut(out: ByteArray) {
        md.digest().copyInto(out, 0, 0, out.size)
    }
}

internal class MessageDigestHasherFactory(val md: MessageDigest) : HasherFactory(md.algorithm, { MessageDigestHasher(md) })
