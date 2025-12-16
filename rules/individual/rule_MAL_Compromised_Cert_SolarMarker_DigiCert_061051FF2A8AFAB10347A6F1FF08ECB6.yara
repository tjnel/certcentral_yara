import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_061051FF2A8AFAB10347A6F1FF08ECB6 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-27"
      version             = "1.0"

      hash                = "1197067d50dd5dd5af12e715e2cc00c0ba1ff738173928bbcfbbad1ee0a52f21"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "TACHOPARTS SP Z O O"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "06:10:51:ff:2a:8a:fa:b1:03:47:a6:f1:ff:08:ec:b6"
      cert_thumbprint     = "8C80793530C12BD6E248E3DF12DB31402B247B5E"
      cert_valid_from     = "2020-11-27"
      cert_valid_to       = "2021-12-01"

      country             = "PL"
      state               = "DOLNOŚLĄSKIE"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "0000654526"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "06:10:51:ff:2a:8a:fa:b1:03:47:a6:f1:ff:08:ec:b6"
      )
}
