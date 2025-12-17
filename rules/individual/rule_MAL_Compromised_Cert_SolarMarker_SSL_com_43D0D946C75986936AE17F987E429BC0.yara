import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_43D0D946C75986936AE17F987E429BC0 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-16"
      version             = "1.0"

      hash                = "dd2e32461bc4ee417a49566db06f29cf84aef11577c9648f4b3f62ac0edf354e"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Гого\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "43:d0:d9:46:c7:59:86:93:6a:e1:7f:98:7e:42:9b:c0"
      cert_thumbprint     = "66EB1188ED0CDC9308F24CA898C3FF455E3E26F5"
      cert_valid_from     = "2023-10-16"
      cert_valid_to       = "2024-10-15"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45219429"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "43:d0:d9:46:c7:59:86:93:6a:e1:7f:98:7e:42:9b:c0"
      )
}
