import "pe"

rule MAL_Compromised_Cert_Chromeloader_Sectigo_00F95B187AE651EEB890723146FB0747F5 {
   meta:
      description         = "Detects Chromeloader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-02"
      version             = "1.0"

      hash                = "9c8ef054cbec26be67f97fc7e17173ec6faa4e4568d724bb67d08df3f4aa8eef"
      malware             = "Chromeloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Invenivia"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:f9:5b:18:7a:e6:51:ee:b8:90:72:31:46:fb:07:47:f5"
      cert_thumbprint     = "76E635B75C879AE52D99FD759BD67BC774499028"
      cert_valid_from     = "2025-01-02"
      cert_valid_to       = "2026-01-02"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:f9:5b:18:7a:e6:51:ee:b8:90:72:31:46:fb:07:47:f5"
      )
}
