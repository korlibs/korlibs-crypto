package korlibs.crypto

import org.bouncycastle.crypto.Digest

fun Digest.asHasher(): HasherFactory = BouncyCastleDigestHasherFactory(this)

fun ByteArray.hash(algo: Digest): Hash = algo.asHasher().digest(this)

internal class BouncyCastleDigestHasher(
    val digest: Digest,
) : NonCoreHasher(0, digest.digestSize, digest.algorithmName) {
    override fun reset(): Hasher {
        digest.reset()
        return this
    }

    override fun update(data: ByteArray, offset: Int, count: Int): Hasher {
        digest.update(data, offset, count)
        return this
    }

    override fun digestOut(out: ByteArray) {
        digest.doFinal(out, 0)
    }
}

internal class BouncyCastleDigestHasherFactory(val digest: Digest) : HasherFactory(digest.algorithmName, { BouncyCastleDigestHasher(digest) })

