import "pe"

rule MAL_Compromised_Cert_Donut_Certum_5F0C0D982DA361C93487CC8CC0B806AD {
   meta:
      description         = "Detects Donut with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-03"
      version             = "1.0"

      hash                = "48633f12c726c33fee82462f8e229b2fa2c366065dae7fec977feceac97a629f"
      malware             = "Donut"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jakub Pawłowski"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "5f:0c:0d:98:2d:a3:61:c9:34:87:cc:8c:c0:b8:06:ad"
      cert_thumbprint     = "D63B7C9BEF7075729FAA5AD86C14305A4660FA4E"
      cert_valid_from     = "2025-07-03"
      cert_valid_to       = "2026-07-03"

      country             = "PL"
      state               = "dolnośląskie"
      locality            = "Bogatynia"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "5f:0c:0d:98:2d:a3:61:c9:34:87:cc:8c:c0:b8:06:ad"
      )
}
