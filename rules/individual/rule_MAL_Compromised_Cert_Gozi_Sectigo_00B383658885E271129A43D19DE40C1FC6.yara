import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_00B383658885E271129A43D19DE40C1FC6 {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-05-27"
      version             = "1.0"

      hash                = "2e0b219c5ac3285a08e126f11c07ea3ac60bc96d16d37c2dc24dd8f68c492a74"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Elekon"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b3:83:65:88:85:e2:71:12:9a:43:d1:9d:e4:0c:1f:c6"
      cert_thumbprint     = "5C706ED4C41F196294C078F9B122BABFFA15DAE4"
      cert_valid_from     = "2020-05-27"
      cert_valid_to       = "2021-05-27"

      country             = "RU"
      state               = "Irkutskaya Obl"
      locality            = "Irkutsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b3:83:65:88:85:e2:71:12:9a:43:d1:9d:e4:0c:1f:c6"
      )
}
