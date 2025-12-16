import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_02B6656292310B84022DB5541BC48FAF {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-21"
      version             = "1.0"

      hash                = "a4649e5f4c93e99352a63345569bf762c0eace3f56f6b8da56f3802923bf058d"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "DILA d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af"
      cert_thumbprint     = "BB58A3D322FD67122804B2924AD1DDC27016E11A"
      cert_valid_from     = "2021-02-21"
      cert_valid_to       = "2022-02-21"

      country             = "SI"
      state               = "???"
      locality            = "Kranj"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af"
      )
}
