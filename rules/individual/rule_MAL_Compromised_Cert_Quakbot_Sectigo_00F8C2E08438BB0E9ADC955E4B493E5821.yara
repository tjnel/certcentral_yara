import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00F8C2E08438BB0E9ADC955E4B493E5821 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-08"
      version             = "1.0"

      hash                = "b66b7bfcdc8d6fb55fe600c20302405a22e1e7b60a0bb1e48a0ccf4e5daf8e50"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "DocsGen Software Solutions Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21"
      cert_thumbprint     = "C4B81197FAC9129D0D1D65FE14FDAC7F2008BFF6"
      cert_valid_from     = "2020-09-08"
      cert_valid_to       = "2021-09-08"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21"
      )
}
