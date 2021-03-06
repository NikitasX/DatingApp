using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DatingApp.API.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace DatingApp.API.Controllers {
    [ApiController]
    [Route ("api/[controller]")]
    public class ValuesController : ControllerBase {
        private readonly ILogger<ValuesController> _logger;
        private readonly DataContext _context;

        public ValuesController (
            ILogger<ValuesController> logger,
            DataContext context) {
            _context = context;
            _logger = logger;
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> GetValues () {

            var values = await _context.Values.ToListAsync ();

            return Ok (values);
        }

        [Authorize(Roles = "Member")]
        [HttpGet ("{id}")]
        public async Task<IActionResult> GetValue (int id) {

            var value = await _context.Values.FirstOrDefaultAsync (x => x.Id == id);

            return Ok (value);
        }
    }
}