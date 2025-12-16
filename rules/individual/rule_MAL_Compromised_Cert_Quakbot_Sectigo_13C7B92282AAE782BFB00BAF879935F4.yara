import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_13C7B92282AAE782BFB00BAF879935F4 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-29"
      version             = "1.0"

      hash                = "ba505ad08b0cc2ca037d5349a1076be579e53b7f20750e779ad07692489eea6f"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "THE WIZARD GIFT CORPORATION"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4"
      cert_thumbprint     = "C664B29247AF0D0365E117694D2BFFEEAC07C019"
      cert_valid_from     = "2020-09-29"
      cert_valid_to       = "2021-09-29"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4"
      )
}
