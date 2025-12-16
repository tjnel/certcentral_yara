import "pe"

rule MAL_Compromised_Cert_GhostRAT_Certum_46C6C62207C137E628861568419977EE {
   meta:
      description         = "Detects GhostRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-30"
      version             = "1.0"

      hash                = "968e5b0abc123f1f2097b5064637a1ab5779205682988880910e3c2d11d51f31"
      malware             = "GhostRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This sample was delivered via phishing, disguised as a image file. This malware is known to be used by a wide range of actors."

      signer              = "北京谷云达吉商贸有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "46:c6:c6:22:07:c1:37:e6:28:86:15:68:41:99:77:ee"
      cert_thumbprint     = "1F75E580CA564F630214EAEF027A426BA2408715"
      cert_valid_from     = "2025-10-30"
      cert_valid_to       = "2026-10-30"

      country             = "CN"
      state               = "北京市"
      locality            = "北京市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "46:c6:c6:22:07:c1:37:e6:28:86:15:68:41:99:77:ee"
      )
}
