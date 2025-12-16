import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_3D4972F14D443D3FCCF56EF6AB6F6CFB {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-17"
      version             = "1.0"

      hash                = "a701979c800e77288f1c28b340b77f62329296d934db727648212e62587bb0f9"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "EPRIS, d.o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "3d:49:72:f1:4d:44:3d:3f:cc:f5:6e:f6:ab:6f:6c:fb"
      cert_thumbprint     = "65EED6B2D21D614C8F031386DADA573B8BFAABEA"
      cert_valid_from     = "2024-07-17"
      cert_valid_to       = "2025-07-17"

      country             = "SI"
      state               = "???"
      locality            = "Kranj"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "3d:49:72:f1:4d:44:3d:3f:cc:f5:6e:f6:ab:6f:6c:fb"
      )
}
