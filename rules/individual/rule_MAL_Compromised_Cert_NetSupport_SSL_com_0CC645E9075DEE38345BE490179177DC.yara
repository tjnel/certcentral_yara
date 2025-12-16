import "pe"

rule MAL_Compromised_Cert_NetSupport_SSL_com_0CC645E9075DEE38345BE490179177DC {
   meta:
      description         = "Detects NetSupport with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-24"
      version             = "1.0"

      hash                = "3a0fc4f5955096ced2382800e3c11da5244279307db7b5371a2295692b862367"
      malware             = "NetSupport"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Kačina Software s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0c:c6:45:e9:07:5d:ee:38:34:5b:e4:90:17:91:77:dc"
      cert_thumbprint     = "C516B5CDADB9BDA44DCD9DE12266FC00AACF0223"
      cert_valid_from     = "2025-01-24"
      cert_valid_to       = "2026-01-24"

      country             = "CZ"
      state               = "Středočeský kraj"
      locality            = "Kolín"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0c:c6:45:e9:07:5d:ee:38:34:5b:e4:90:17:91:77:dc"
      )
}
