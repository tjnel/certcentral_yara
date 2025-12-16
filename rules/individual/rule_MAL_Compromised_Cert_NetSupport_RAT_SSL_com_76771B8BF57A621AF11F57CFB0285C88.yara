import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_76771B8BF57A621AF11F57CFB0285C88 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-06"
      version             = "1.0"

      hash                = "b8d481bfba169aa3d77b0c49cbb93d907417357d6db7ecdaa280623897c3ecec"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Satago Software Solutions Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "76:77:1b:8b:f5:7a:62:1a:f1:1f:57:cf:b0:28:5c:88"
      cert_thumbprint     = "AF9A758C6A97D52083416775446940321909433E"
      cert_valid_from     = "2024-09-06"
      cert_valid_to       = "2025-09-06"

      country             = "PL"
      state               = "Lesser Poland Voivodeship"
      locality            = "Kraków"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "76:77:1b:8b:f5:7a:62:1a:f1:1f:57:cf:b0:28:5c:88"
      )
}
