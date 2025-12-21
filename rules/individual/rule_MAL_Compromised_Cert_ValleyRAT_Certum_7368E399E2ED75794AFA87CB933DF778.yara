import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_7368E399E2ED75794AFA87CB933DF778 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-19"
      version             = "1.0"

      hash                = "930fd881cec8867db13d789dd138441cdf2df2a05df8804baa93c267b5934940"
      malware             = "ValleyRAT"
      malware_type        = "Remote access trojan"
      malware_notes       = "See this recent blogpost to learn about ValleyRAT: https://research.checkpoint.com/2025/cracking-valleyrat-from-builder-secrets-to-kernel-rootkits/. This was identified as ValleyRAT by multiple sandboxes."

      signer              = "泉州浩英科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "73:68:e3:99:e2:ed:75:79:4a:fa:87:cb:93:3d:f7:78"
      cert_thumbprint     = "85686DEA6A1E71197CEDD79DB82BE225DF97C744"
      cert_valid_from     = "2025-12-19"
      cert_valid_to       = "2026-12-19"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "73:68:e3:99:e2:ed:75:79:4a:fa:87:cb:93:3d:f7:78"
      )
}
