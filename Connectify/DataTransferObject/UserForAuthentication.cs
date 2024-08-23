using System.ComponentModel.DataAnnotations;

namespace Connectify.DataTransferObject
{
    public record UserForAuthentication
    {
        [Required(ErrorMessage = "User name is required")]
        public string? UserName { get; init; }

        [Required(ErrorMessage = "Password name is required")]
        public string? Password { get; init; }
    }
}
