import "pe"

rule MAL_Compromised_Cert_MeshAgentTrojan_GlobalSign_480ED01C27E3CD365556EECE {
   meta:
      description         = "Detects MeshAgentTrojan with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-31"
      version             = "1.0"

      hash                = "cdb4e4b35b002bd64e701f3c1e8b147b96cb0907bcc88ead92521777781ca2d1"
      malware             = "MeshAgentTrojan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Leap Grace Electronics Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "48:0e:d0:1c:27:e3:cd:36:55:56:ee:ce"
      cert_thumbprint     = "EC1453D0BCEA9F9B416D32308EA9534865BE71BD"
      cert_valid_from     = "2024-07-31"
      cert_valid_to       = "2025-08-01"

      country             = "CN"
      state               = "Shandong"
      locality            = "Jinan"
      email               = "???"
      rdn_serial_number   = "91370102MA3C9D0U34"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "48:0e:d0:1c:27:e3:cd:36:55:56:ee:ce"
      )
}
