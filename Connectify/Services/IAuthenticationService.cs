using Connectify.DataTransferObject;
using Microsoft.AspNetCore.Identity;

namespace Connectify.Services
{
    public interface IAuthenticationService
    {
        Task<IdentityResult> RegisterUser(UserForRegistrationDto userForRegistrationDto);

        Task<bool> ValidateUser(UserForAuthentication userForAuth);
        String CreateToken();

        Task<string> ForgotPassword(string emailOrUserName);

        Task<IdentityResult> ResetPassword(PasswordResetDto passwordResetDto);

        Task<IdentityResult> ChangePassword(ChangePasswordDto changePasswordDto);
    }
}
