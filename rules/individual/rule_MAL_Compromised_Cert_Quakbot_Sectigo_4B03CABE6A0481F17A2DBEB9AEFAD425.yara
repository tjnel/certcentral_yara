import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_4B03CABE6A0481F17A2DBEB9AEFAD425 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-10"
      version             = "1.0"

      hash                = "f15e75823d25a23ed5ec3c5236b514add35a9a104803f0e16527c087f8a7c26b"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "RASSVET, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25"
      cert_thumbprint     = "25ECC0F4B78BCC02498CEAF7A2DE2883574ACB1C"
      cert_valid_from     = "2020-10-10"
      cert_valid_to       = "2021-10-10"

      country             = "RU"
      state               = "???"
      locality            = "Moskva"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25"
      )
}
