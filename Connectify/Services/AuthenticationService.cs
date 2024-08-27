using AutoMapper;
using Connectify.DataTransferObject;
using Connectify.Exceptions;
using Connectify.Logger;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Connectify.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IMapper _mapper;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILoggerManager _logger;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private IdentityUser? _identityUser;
       

        public AuthenticationService(IMapper mapper, UserManager<IdentityUser> userManager, ILoggerManager logger, IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _mapper = mapper;
            _userManager = userManager;
            _logger = logger;
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }

        public string CreateToken()
        {
            var signingCredentials = GetSigningCredentials();
            var claims =  GetClaimsByUserName();

            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }

       

        public async Task<IdentityResult> RegisterUser(UserForRegistrationDto userForRegistrationDto)
        {
            var user = _mapper.Map<IdentityUser>(userForRegistrationDto);

            var result = await _userManager.CreateAsync(user, userForRegistrationDto.Password);

            return result;
        }

        public async Task<bool> ValidateUser(UserForAuthentication userForAuth)
        {
            _identityUser = await _userManager.FindByNameAsync(userForAuth.UserName);

            if (_identityUser == null)
                _identityUser = await _userManager.FindByEmailAsync(userForAuth.UserName);

            var result = (_identityUser != null && await _userManager.CheckPasswordAsync(_identityUser, userForAuth.Password));

            if (!result)
                _logger.LogWarn($"{nameof(ValidateUser)}: Authentication failed. Wrong user name or password. ");
            return result;
        }




        private SigningCredentials GetSigningCredentials()
        {
            var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SECRET"));

            var secret = new SymmetricSecurityKey(key);

            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        private List<Claim> GetClaimsByUserName()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, _identityUser.UserName)
            };
           

            return claims;
        }

       

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("JwtSetting");

            var tokenOptions = new JwtSecurityToken(
                issuer: jwtSettings["validIssuer"],
                audience: jwtSettings["validAudience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["expires"])),
                signingCredentials: signingCredentials
                );
                return tokenOptions;
                
                
        }

       
        public async Task<string> ForgotPassword(string emailOrUserName)
        {
           var token =await ResetToken(emailOrUserName);

            return token;
                
            
        }

        private async Task<string> ResetToken(string emailOrUserName)
        {
            _identityUser = await _userManager.FindByEmailAsync(emailOrUserName);

           if (_identityUser == null)
                _identityUser = await _userManager.FindByNameAsync(emailOrUserName);

            if(_identityUser is null) 
                throw  new UserNotFoundException(emailOrUserName);

             var token = await _userManager.GeneratePasswordResetTokenAsync(_identityUser);

                return token;

        }

        public async Task<IdentityResult> ResetPassword(PasswordResetDto passwordResetDto)
        {
            _identityUser = await _userManager.FindByEmailAsync(passwordResetDto.EmailORUserName);

            if (_identityUser is null)
                _identityUser = await _userManager.FindByNameAsync(passwordResetDto.EmailORUserName);

            if (_identityUser is null)
                throw new UserNotFoundException(passwordResetDto.EmailORUserName);


            var resetPassword = await _userManager.ResetPasswordAsync(_identityUser, passwordResetDto.Token, passwordResetDto.NewPassword);

                return resetPassword;
            
        }

        public async Task<IdentityResult> ChangePassword(ChangePasswordDto changePasswordDto)
        {
            var username = _httpContextAccessor.HttpContext?.User?.Identity?.Name;

            _identityUser = await _userManager.FindByEmailAsync(username);

            var result = await _userManager.ChangePasswordAsync(_identityUser, changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);

            return result;
            
        }
    }
}
