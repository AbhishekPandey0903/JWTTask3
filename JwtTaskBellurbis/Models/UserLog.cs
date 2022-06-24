using System.ComponentModel.DataAnnotations;

namespace JwtTaskBellurbis.Models
{
    public class UserLog
    {
        [Key]
        public int UserId { get; set; }

        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }

    }
}
