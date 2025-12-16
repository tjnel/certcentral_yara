import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_235A083100CDC9C67691B31B1E958A0E {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-08-24"
      version             = "1.0"

      hash                = "a2ebd484b939b5c5bd273de83e56e46b56d250e144b6d467e89d1df4a26c4ee8"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Databytes Software Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "23:5a:08:31:00:cd:c9:c6:76:91:b3:1b:1e:95:8a:0e"
      cert_thumbprint     = "19617F89E0E4754976A4BAA471B538893B042D40"
      cert_valid_from     = "2022-08-24"
      cert_valid_to       = "2023-08-24"

      country             = "GB"
      state               = "???"
      locality            = "Cookstown"
      email               = "???"
      rdn_serial_number   = "NI653695"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "23:5a:08:31:00:cd:c9:c6:76:91:b3:1b:1e:95:8a:0e"
      )
}
