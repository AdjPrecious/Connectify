using Connectify.DataTransferObject;
using Connectify.DataTransferObject.UserDto;
using Connectify.Model.Identity;
using Connectify.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Connectify.Controllers
{
    [Route("api/authentication")]
    [ApiController]
    [ApiExplorerSettings(GroupName = "v1")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IServiceManager _service;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthenticationController(IServiceManager service, UserManager<IdentityUser> userManager)
        {
            _service = service;
            _userManager = userManager;
        }

        [HttpPost("createUser")]
        public async Task<IActionResult> RegisterUser([FromBody] UserForRegistrationDto userForRegistration)
        {
            var result = await _service.AuthenticationService.RegisterUser(userForRegistration);
            if(!result.Succeeded)
            {
                foreach(var error in result.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }
                return BadRequest(ModelState);
            }

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForAuthentication user)
        {
            if (!await _service.AuthenticationService.ValidateUser(user))
            return  Unauthorized();

            return Ok(new { Token =  _service.AuthenticationService.CreateToken() });
        }

        [HttpPost("forgotpassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(string emailOrUserName)
        {


           var result =  await _service.AuthenticationService.ForgotPassword(emailOrUserName);
            if (result is null)
                return BadRequest(ModelState);

            return Ok(result);
        }

        [HttpPost("resetpassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(PasswordResetDto resetPassword)
        {
            var result = await _service.AuthenticationService.ResetPassword(resetPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }
                return BadRequest(ModelState);
            }

            return StatusCode(201);
        }

        [Authorize]
        [HttpPost("changepassword")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDto changePasswordDto)
        {
           
            var result = await _service.AuthenticationService.ChangePassword(changePasswordDto);
            if (!result.Succeeded)
            {
                foreach(var error in result.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }
                return BadRequest(ModelState);
            }
            return StatusCode(201);
        }
    }
}
