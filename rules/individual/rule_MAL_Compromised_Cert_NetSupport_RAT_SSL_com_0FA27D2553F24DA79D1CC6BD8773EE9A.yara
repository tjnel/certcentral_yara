import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_0FA27D2553F24DA79D1CC6BD8773EE9A {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-25"
      version             = "1.0"

      hash                = "113290aaa5c0b0793d50de6819f2b2eead5e321e9300d91b9a36d62ba8e5bbc1"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "CYNC LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0f:a2:7d:25:53:f2:4d:a7:9d:1c:c6:bd:87:73:ee:9a"
      cert_thumbprint     = "E9007755CFE5643D18618786DE1995914098307F"
      cert_valid_from     = "2024-07-25"
      cert_valid_to       = "2025-07-25"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "13066343"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0f:a2:7d:25:53:f2:4d:a7:9d:1c:c6:bd:87:73:ee:9a"
      )
}
