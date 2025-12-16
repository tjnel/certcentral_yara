import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_66F965DEE2E387D6B5233CF39DFDE75F {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-18"
      version             = "1.0"

      hash                = "e16ef57ddac8cf1ab3b4b20e1915bd0790eb049aabff91f4576c883246914de4"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "BERCIS Software SIA"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "66:f9:65:de:e2:e3:87:d6:b5:23:3c:f3:9d:fd:e7:5f"
      cert_thumbprint     = "2894E68AA4B8AF304F6877D39A218214B458D71C"
      cert_valid_from     = "2024-07-18"
      cert_valid_to       = "2025-07-18"

      country             = "LV"
      state               = "???"
      locality            = "Riga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "66:f9:65:de:e2:e3:87:d6:b5:23:3c:f3:9d:fd:e7:5f"
      )
}
