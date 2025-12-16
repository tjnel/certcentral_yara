import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_DigiCert_0E8AA328AF207CE8BCAE1DC15C626188 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-27"
      version             = "1.0"

      hash                = "45ff625f17a1e9ad65dd94c376034148d6d8eee8a41b1209f566a907f5d6d6c7"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "PRO SAT SRL"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:8a:a3:28:af:20:7c:e8:bc:ae:1d:c1:5c:62:61:88"
      cert_thumbprint     = "96AD6679F52FEB25C81DEF440003A4AB737718C5"
      cert_valid_from     = "2021-07-27"
      cert_valid_to       = "2023-07-27"

      country             = "RO"
      state               = "???"
      locality            = "ALBA IULIA"
      email               = "???"
      rdn_serial_number   = "J01/557/1993"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:8a:a3:28:af:20:7c:e8:bc:ae:1d:c1:5c:62:61:88"
      )
}
