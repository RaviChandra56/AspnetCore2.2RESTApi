﻿using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TweetBook.Domain
{
    public class RefreshToken
    {
        [Key]
        public string Token { get; set; }
        public string JwiId { get; set; }
        public DateTime CreationDate { get; set; }
        public DateTime ExpireDate { get; set; }
        public bool Used { get; set; }
        public bool Invalidated { get; set; }
        public string UserId { get; set; }

        [ForeignKey(nameof(UserId))]
        public IdentityUser User { get; set; }
    }
}
