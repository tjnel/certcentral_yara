import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_7B1CBB403DB37D45ABC2C210 {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-30"
      version             = "1.0"

      hash                = "83db121492b9df5dfb359c830d0adb7deb9107fbf0101ba7ae4c0a863b0bd723"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "MSSM UJJAWAL NIDHI LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7b:1c:bb:40:3d:b3:7d:45:ab:c2:c2:10"
      cert_thumbprint     = "BD3359A19103FBD64678451D2C77E0982BC5B828"
      cert_valid_from     = "2025-07-30"
      cert_valid_to       = "2026-07-31"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "ujjawalnidhi.abhi@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7b:1c:bb:40:3d:b3:7d:45:ab:c2:c2:10"
      )
}
