import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_012E3520CF2A48ABE44FF45C532FEB12 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-02"
      version             = "1.0"

      hash                = "652b6a4cc3727974f457a0ce43f5a42ee03cd9135faf3fcae83b8155b3944086"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "amir dow"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "01:2e:35:20:cf:2a:48:ab:e4:4f:f4:5c:53:2f:eb:12"
      cert_thumbprint     = "2735C134B87B896909C315945DEDFBB1A4AC79BA"
      cert_valid_from     = "2024-10-02"
      cert_valid_to       = "2027-10-02"

      country             = "IL"
      state               = "Northern"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "01:2e:35:20:cf:2a:48:ab:e4:4f:f4:5c:53:2f:eb:12"
      )
}
