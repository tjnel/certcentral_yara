import "pe"

rule MAL_Compromised_Cert_FakeNSFW_SSL_com_5ECDA0686C2632163BC7F9F342366FF4 {
   meta:
      description         = "Detects FakeNSFW with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-26"
      version             = "1.0"

      hash                = "a776fd03c3fc1596d24f78cce144cb83f1fba242c6c158290294c36f0e845829"
      malware             = "FakeNSFW"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "PITTORE S.R.L."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5e:cd:a0:68:6c:26:32:16:3b:c7:f9:f3:42:36:6f:f4"
      cert_thumbprint     = "86800EEDB60DE91568AE3BA0E3D5963F6AEE7CAD"
      cert_valid_from     = "2025-06-26"
      cert_valid_to       = "2026-06-26"

      country             = "AR"
      state               = "Buenos Aires Province"
      locality            = "Buenos Aires"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5e:cd:a0:68:6c:26:32:16:3b:c7:f9:f3:42:36:6f:f4"
      )
}
