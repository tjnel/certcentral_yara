import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_767762D952D581A77D277D74A02485EC {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-04"
      version             = "1.0"

      hash                = "32f886142de76f09b1e7229a79e66eb46889251ebf871e4df3b6de7fd5cef749"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Soft Design B.V."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "76:77:62:d9:52:d5:81:a7:7d:27:7d:74:a0:24:85:ec"
      cert_thumbprint     = "C2562BC3BC0640A556E285409F2EC88EBF6D799E"
      cert_valid_from     = "2025-09-04"
      cert_valid_to       = "2026-09-04"

      country             = "NL"
      state               = "South Holland"
      locality            = "Bergschenhoek"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "76:77:62:d9:52:d5:81:a7:7d:27:7d:74:a0:24:85:ec"
      )
}
