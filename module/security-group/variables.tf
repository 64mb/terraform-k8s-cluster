variable "name" {
  type = string
}

variable "network_id" {
  type = string
}

variable "security_rules" {
  type = object({
    egress : list(object({ # outcoming
      proto     = string
      from_port = optional(number)
      to_port   = optional(number)
      port      = optional(number)
      target    = optional(string)
      desc      = optional(string)
      cidr_v4   = optional(list(string))
      cidr_v6   = optional(list(string))
    }))
    ingress : list(object({ # incoming
      proto     = string
      from_port = optional(number)
      to_port   = optional(number)
      port      = optional(number)
      target    = optional(string)
      desc      = optional(string)
      cidr_v4   = optional(list(string))
      cidr_v6   = optional(list(string))
    }))
  })
}
