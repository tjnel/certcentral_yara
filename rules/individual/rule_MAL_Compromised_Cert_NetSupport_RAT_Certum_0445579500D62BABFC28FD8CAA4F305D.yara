import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_0445579500D62BABFC28FD8CAA4F305D {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-05"
      version             = "1.0"

      hash                = "dd004507cf28c1a965b6475afa071e0aad2644056a84e173ce74b73cbcc8facb"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Satago Software Solutions Sp. z o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "04:45:57:95:00:d6:2b:ab:fc:28:fd:8c:aa:4f:30:5d"
      cert_thumbprint     = "57F629EDE7002C2BEA1AF8B60062C303FA12F957"
      cert_valid_from     = "2024-09-05"
      cert_valid_to       = "2025-09-05"

      country             = "PL"
      state               = "???"
      locality            = "Kraków"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "04:45:57:95:00:d6:2b:ab:fc:28:fd:8c:aa:4f:30:5d"
      )
}
