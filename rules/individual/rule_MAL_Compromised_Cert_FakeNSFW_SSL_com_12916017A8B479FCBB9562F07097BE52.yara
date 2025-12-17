import "pe"

rule MAL_Compromised_Cert_FakeNSFW_SSL_com_12916017A8B479FCBB9562F07097BE52 {
   meta:
      description         = "Detects FakeNSFW with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-13"
      version             = "1.0"

      hash                = "579400d97efabfc565ea1b11e85149767cd69f98f9b0072a25559fb076ed479c"
      malware             = "FakeNSFW"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "M BIT SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "12:91:60:17:a8:b4:79:fc:bb:95:62:f0:70:97:be:52"
      cert_thumbprint     = "C3E157B3168C6893B4B94CA64DEDE002AACFAB34"
      cert_valid_from     = "2025-06-13"
      cert_valid_to       = "2026-06-13"

      country             = "PL"
      state               = "Malopolskie"
      locality            = "Nowy Sacz"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "12:91:60:17:a8:b4:79:fc:bb:95:62:f0:70:97:be:52"
      )
}
