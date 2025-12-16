import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_3696883055975D571199C6B5D48F3CD5 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-03"
      version             = "1.0"

      hash                = "dec2d24131b54bda92b59c49acc410da4af20a730b3113c0472479ac168e3a81"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Korist Networks Incorporated"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5"
      cert_thumbprint     = "1D2F7867DCCAC28A856CF884E4DB54E7A99D1382"
      cert_valid_from     = "2020-09-03"
      cert_valid_to       = "2021-09-03"

      country             = "CA"
      state               = "Ontario"
      locality            = "Brampton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5"
      )
}
