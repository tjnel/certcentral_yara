import "pe"

rule MAL_Compromised_Cert_FakeCursorAI_SSL_com_39E13CD290AD5B121B45BAE4C5677380 {
   meta:
      description         = "Detects FakeCursorAI with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "3a040f157773370101bbd9cc9ef296ff28432d9b8611cf640c5726657a9bd606"
      malware             = "FakeCursorAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CODE FASHION SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "39:e1:3c:d2:90:ad:5b:12:1b:45:ba:e4:c5:67:73:80"
      cert_thumbprint     = "1DEEBE5AADAF629E65FBE7DAFB39830B0A009BE9"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2026-09-10"

      country             = "PL"
      state               = "Łódź Voivodeship"
      locality            = "Ksawerów"
      email               = "???"
      rdn_serial_number   = "0000848972"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "39:e1:3c:d2:90:ad:5b:12:1b:45:ba:e4:c5:67:73:80"
      )
}
