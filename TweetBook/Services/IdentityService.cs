using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TweetBook.Data;
using TweetBook.Domain;
using TweetBook.Options;

namespace TweetBook.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly UserManager<IdentityUser> _userManger;
        private readonly JwtSettings _jwtSettings;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly DataContext _dataContext;

        public IdentityService(UserManager<IdentityUser> userManger, JwtSettings jwtSettings, TokenValidationParameters tokenValidationParameters, DataContext dataContext)
        {
            _userManger = userManger;
            _jwtSettings = jwtSettings;
            _tokenValidationParameters = tokenValidationParameters;
            _dataContext = dataContext;
        }

        public async Task<AuthenticationResult> RegisterAsync(string email, string password)
        {
            var existingsuser = await _userManger.FindByEmailAsync(email);

            if (existingsuser != null)
            {
                return new AuthenticationResult
                {
                    Errors = new[] { "User with email address already exists" }
                };
            }

            var newUser = new IdentityUser
            {
                Email = email,
                UserName = email
            };

            var createdUser = await _userManger.CreateAsync(newUser, password);

            if (!createdUser.Succeeded)
            {
                return new AuthenticationResult
                {
                    Errors = createdUser.Errors.Select(x => x.Description)
                };
            }

            return await GenerateAuthenticationResultForUser(newUser);
        }

        public async Task<AuthenticationResult> LoginAsync(string email, string password)
        {
            var user = await _userManger.FindByEmailAsync(email);

            if (user == null)
            {
                return new AuthenticationResult
                {
                    Errors = new[] { "User does not exists" }
                };
            }

            var userHasValidPassword = await _userManger.CheckPasswordAsync(user, password);
            if (!userHasValidPassword)
            {
                return new AuthenticationResult
                {
                    Errors = new[] { "User/Password combination is wrong" }
                };
            }

            return await GenerateAuthenticationResultForUser(user);
        }

        public async Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken)
        {
            var validateToken = GetPrincipleFromToken(token);
            if (validateToken == null)
            {
                return new AuthenticationResult { Errors = new[] { "Invalid Token"} };
            }

            var expityDateUnix = long.Parse(validateToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            var expiryDateTimeUtc = new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(expityDateUnix);
            if (expiryDateTimeUtc > DateTime.UtcNow)
            {
                return new AuthenticationResult { Errors = new[]{ "This token hasn't expired yet"} };
            }

            var jti = validateToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            var storedRefreshToken = await _dataContext.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken);
            if (storedRefreshToken == null)
            {
                return new AuthenticationResult { Errors = new[] { "This refresh token does not exists" } };
            }

            if (DateTime.UtcNow > storedRefreshToken.ExpireDate)
            {
                return new AuthenticationResult { Errors = new[] { "This refresh token hasn expired" } };
            }
            if (storedRefreshToken.Used)
            {
                return new AuthenticationResult { Errors = new[] { "This refresh token has been used" } };
            }
            if (storedRefreshToken.JwiId != jti)
            {
                return new AuthenticationResult { Errors = new[] { "This refresh token does not match this JWT" } };
            }

            storedRefreshToken.Used = true;
            _dataContext.RefreshTokens.Update(storedRefreshToken);
            await _dataContext.SaveChangesAsync();

            var user = await _userManger.FindByEmailAsync(validateToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value);
            return await GenerateAuthenticationResultForUser(user);
        }

        private async Task<AuthenticationResult> GenerateAuthenticationResultForUser(IdentityUser newUser)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, newUser.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, newUser.Email),
                    new Claim("id", newUser.Id)
                }),
                Expires = DateTime.UtcNow.Add(_jwtSettings.TokenLifeTime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            var refreshToken = new RefreshToken
            {
                JwiId = token.Id,
                UserId = newUser.Id,
                CreationDate = DateTime.UtcNow,
                ExpireDate = DateTime.UtcNow.AddMonths(6)
            };

            await _dataContext.RefreshTokens.AddAsync(refreshToken);
            await _dataContext.SaveChangesAsync();

            return new AuthenticationResult
            {
                Success = true,
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token
            };
        }

        private ClaimsPrincipal GetPrincipleFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principle = tokenHandler.ValidateToken(token, _tokenValidationParameters, out var validatedToken);
                if (!IsJwtValidSecurityAlgorithm(validatedToken))
                {
                    return null;
                }
                return principle;
            }
            catch
            {
                return null;
            }
        }

        private bool IsJwtValidSecurityAlgorithm(SecurityToken validatedToken)
        {
            return (validatedToken is JwtSecurityToken jwtSecurityToken) &&
                jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
        }
    }
}
