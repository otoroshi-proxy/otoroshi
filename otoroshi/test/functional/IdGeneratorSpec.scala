package functional

import org.scalatest.OptionValues
import otoroshi.security.IdGenerator

// pure logic. randomness quality itself cannot be asserted in a test, so what is pinned here is the
// shape and alphabet contract of the generators, plus one measurable entropy defect
class IdGeneratorSpec
    extends org.scalatest.wordspec.AnyWordSpec
    with org.scalatest.matchers.must.Matchers
    with OptionValues {

  val hexDigits = "0123456789abcdef".toSet

  "IdGenerator.token" should {

    "have the requested length" in {
      IdGenerator.token(64).length mustBe 64
      IdGenerator.token(16).length mustBe 16
    }

    "only use alphanumeric characters" in {
      val alphabet = ('a' to 'z').toSet ++ ('A' to 'Z').toSet ++ ('0' to '9').toSet
      IdGenerator.token(4096).toSet.diff(alphabet) mustBe empty
    }

    "keep lowerCaseToken lower case, sized or not" in {
      val alphabet = ('a' to 'z').toSet ++ ('0' to '9').toSet
      IdGenerator.lowerCaseToken(4096).toSet.diff(alphabet) mustBe empty
      IdGenerator.lowerCaseToken.toSet.diff(alphabet) mustBe empty
    }

    "not repeat itself" in {
      (0 until 200).map(_ => IdGenerator.token(32)).toSet.size mustBe 200
    }
  }

  "IdGenerator.uuid" should {

    "keep its shape" in {
      val uuid = IdGenerator.uuid
      uuid.length mustBe 37
      Seq(9, 14, 19, 24).foreach(i => uuid.charAt(i) mustBe '-')
      uuid.charAt(15) mustBe '4'
      Set('8', '9', 'a', 'b') must contain(uuid.charAt(20))
    }

    "only use hex digits outside of the separators" in {
      val chars = (0 until 200).map(_ => IdGenerator.uuid).mkString.toSet - '-'
      chars.diff(hexDigits) mustBe empty
    }

    // (random.nextDouble() * 15.0).toInt only ever yields 0 to 14, so the last entry of the hex
    // alphabet was unreachable: every position carried log2(15) bits instead of 4
    "reach every hex digit" in {
      val chars = (0 until 200).map(_ => IdGenerator.uuid).mkString.toSet - '-'
      hexDigits.diff(chars) mustBe empty
    }

    "not repeat itself" in {
      (0 until 200).map(_ => IdGenerator.uuid).toSet.size mustBe 200
    }
  }
}
