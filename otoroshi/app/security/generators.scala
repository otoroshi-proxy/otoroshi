package otoroshi.security

import otoroshi.env.Env

import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import scala.util.Try

class IdGenerator(generatorId: Long) {
  def nextId(): Long          = IdGenerator.nextId(generatorId)
  def nextIdSafe(): Try[Long] = Try(nextId())
  def nextIdStr(): String     = IdGenerator.nextIdStr(generatorId)
}

object IdGenerator {

  private val LOWER_CASE_CHARACTERS =
    "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray.map(_.toString)
  private val CHARACTERS            =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray.map(_.toString)
  private val EXTENDED_CHARACTERS   =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*$%)([]!=+-_:/;.><&".toCharArray.map(_.toString)
  private val INIT_STRING           = for (i <- 0 to 15) yield Integer.toHexString(i)

  // apikey secrets and the like are drawn from here, so the generator must not be predictable from
  // previously observed output. one instance per thread rather than a shared one: SecureRandom locks
  // internally and uuid is called on every request
  private val secureRandom: ThreadLocal[SecureRandom] = ThreadLocal.withInitial(() => new SecureRandom())

  private val minus         = 1288834974657L
  private val counter       = new AtomicLong(-1L)
  private val lastTimestamp = new AtomicLong(-1L)
  private val duplicates    = new AtomicLong(-0L)

  def apply(generatorId: Long) = new IdGenerator(generatorId)

  def nextId(generatorId: Long): Long =
    synchronized {
      if (generatorId > 1024L) throw new RuntimeException("Generator id can't be larger than 1024")
      val timestamp = System.currentTimeMillis
      if (timestamp < lastTimestamp.get()) throw new RuntimeException("Clock is running backward. Sorry :-(")
      lastTimestamp.set(timestamp)
      counter.compareAndSet(4095, -1L)
      ((timestamp - minus) << 22L) | (generatorId << 10L) | counter.incrementAndGet()
    }

  def nextIdStr(generatorId: Long): String =
    synchronized {
      if (generatorId > 1024L) throw new RuntimeException("Generator id can't be larger than 1024")
      val timestamp = System.currentTimeMillis
      val append    = if (timestamp < lastTimestamp.get()) s"-${duplicates.incrementAndGet() + generatorId}" else ""
      lastTimestamp.set(timestamp)
      counter.compareAndSet(4095, -1L)
      (((timestamp - minus) << 22L) | (generatorId << 10L) | counter.incrementAndGet()).toString + append
    }

  // the 32 non fixed characters are one nibble each, so a uuid costs a single draw of 16 bytes
  // instead of one draw per character. the previous `(nextDouble * 15).toInt` also never reached the
  // last hex digit, leaving log2(15) bits per character instead of 4
  def uuid: String = {
    val bytes = new Array[Byte](16)
    secureRandom.get().nextBytes(bytes)
    val builder = new java.lang.StringBuilder(37)
    var nibble  = 0
    var index   = 0
    while (index <= 36) {
      index match {
        case 9 | 14 | 19 | 24 => builder.append('-')
        case 15               => builder.append('4')
        case _                =>
          val byte  = bytes(nibble / 2) & 0xff
          val value = if (nibble % 2 == 0) byte >>> 4 else byte & 0x0f
          nibble += 1
          builder.append(INIT_STRING(if (index == 20) (value & 0x03) | 8 else value))
      }
      index += 1
    }
    builder.toString
  }

  def token(characters: Array[String], size: Int): String = {
    val random = secureRandom.get()
    (for {
      i <- 0 to size - 1
    } yield characters(random.nextInt(characters.size))).mkString("")
  }

  def token(size: Int): String                                = token(CHARACTERS, size)
  def token: String                                           = token(64)
  def lowerCaseToken(size: Int): String                       = token(LOWER_CASE_CHARACTERS, size)
  def lowerCaseToken: String                                  = token(LOWER_CASE_CHARACTERS, 64)
  def extendedToken(size: Int): String                        = token(EXTENDED_CHARACTERS, size)
  def extendedToken: String                                   = token(EXTENDED_CHARACTERS, 64)
  def namedToken(prefix: String, size: Int, env: Env): String = namedToken(prefix, size, env.env)
  def namedToken(prefix: String, size: Int, env: String): String = {
    env match {
      case "prod" => s"${prefix}_${token(size)}"
      case _      => s"${prefix}_${env}_${token(size)}"
    }
  }
  def namedId(prefix: String, env: Env): String               = namedId(prefix, env.env)
  def namedId(prefix: String, env: String): String = {
    env match {
      case "prod" => s"${prefix}_${UUID.randomUUID().toString}"
      case _      => s"${prefix}_${env}_${UUID.randomUUID().toString}"
    }
  }
}
