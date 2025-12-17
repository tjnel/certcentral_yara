import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_4E3DC08BA3B230C5968A4C8B6B1B3C64 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-09"
      version             = "1.0"

      hash                = "88bcc4eacf3c0dd26c57dfdd42da085eeff0bcc4c1106eceeba466c0a05fc1e5"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CÔNG TY TNHH XB FLOW TECHNOLOGIES"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4e:3d:c0:8b:a3:b2:30:c5:96:8a:4c:8b:6b:1b:3c:64"
      cert_thumbprint     = "24FEB829E1A0DD9AB71B7EF485CB1F026BCBFE9F"
      cert_valid_from     = "2025-12-09"
      cert_valid_to       = "2027-01-08"

      country             = "VN"
      state               = "Quảng Trị"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "3101145367"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4e:3d:c0:8b:a3:b2:30:c5:96:8a:4c:8b:6b:1b:3c:64"
      )
}
