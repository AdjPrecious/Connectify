using Microsoft.AspNetCore.Identity;

namespace Connectify.Model.Identity
{
    public class User : IdentityUser
    {
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
