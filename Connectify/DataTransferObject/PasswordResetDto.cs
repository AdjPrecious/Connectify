using System.ComponentModel.DataAnnotations;

namespace Connectify.DataTransferObject
{
    public record PasswordResetDto
    {
        [Required]
        [DataType(DataType.Password)]
        
        public string? NewPassword { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match")]
        public string? ConfirmPassword {  get; set; }

        [Required]
        public string? Token {  get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        public string? EmailORUserName { get; set; }



    }
}
