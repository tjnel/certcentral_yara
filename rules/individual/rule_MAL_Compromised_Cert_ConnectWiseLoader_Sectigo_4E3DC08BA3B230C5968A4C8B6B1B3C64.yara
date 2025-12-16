import "pe"

rule MAL_Compromised_Cert_ConnectWiseLoader_Sectigo_4E3DC08BA3B230C5968A4C8B6B1B3C64 {
   meta:
      description         = "Detects ConnectWiseLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-09"
      version             = "1.0"

      hash                = "88bcc4eacf3c0dd26c57dfdd42da085eeff0bcc4c1106eceeba466c0a05fc1e5"
      malware             = "ConnectWiseLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware was observed being downloaded with filenames such as \"Facebook_Video20251122.mp4 Facebook.com\" \"screen_video_iphone.mp4 Drive.google.com\". This signer was also previously used with other RMM tools and similar filenames."

      signer              = "CÔNG TY TNHH XB FLOW TECHNOLOGIES"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4e:3d:c0:8b:a3:b2:30:c5:96:8a:4c:8b:6b:1b:3c:64"
      cert_thumbprint     = "24FEB829E1A0DD9AB71B7EF485CB1F026BCBFE9F"
      cert_valid_from     = "2025-12-09"
      cert_valid_to       = "2027-01-08"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4e:3d:c0:8b:a3:b2:30:c5:96:8a:4c:8b:6b:1b:3c:64"
      )
}
