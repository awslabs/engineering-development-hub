(function($) {
  "use strict"; // Start of use strict

  // Restore sidebar state from localStorage on page load
  if (localStorage.getItem("sidebarToggled") === "true") {
    $("body").addClass("sidebar-toggled");
    $(".sidebar").addClass("toggled").hide();
    $("#sidebarOpenBtn").show();
  }

  // Toggle the side navigation
  $(document).on('click', '#sidebarToggle, #sidebarToggleTop, #sidebarOpenBtn', function(e) {
    $("body").toggleClass("sidebar-toggled");
    var $sidebar = $(".sidebar");
    if ($sidebar.hasClass("toggled")) {
      $sidebar.removeClass("toggled").show();
      $("#sidebarOpenBtn").hide();
      localStorage.setItem("sidebarToggled", "false");
    } else {
      $('.sidebar .collapse').collapse('hide');
      $sidebar.addClass("toggled").hide();
      $("#sidebarOpenBtn").show();
      localStorage.setItem("sidebarToggled", "true");
    }
  });

  // Close any open menu accordions when window is resized below 768px
  $(window).resize(function() {
    if ($(window).width() < 768) {
      $('.sidebar .collapse').collapse('hide');
    }
  });

  // Prevent the content wrapper from scrolling when the fixed side navigation hovered over
  $('body.fixed-nav .sidebar').on('mousewheel DOMMouseScroll wheel', function(e) {
    if ($(window).width() > 768) {
      const e0 = e.originalEvent,
        delta = e0.wheelDelta || -e0.detail;
      this.scrollTop += (delta < 0 ? 1 : -1) * 30;
      e.preventDefault();
    }
  });

  // Scroll to top button appear
  $(document).on('scroll', function() {
    const scrollDistance = $(this).scrollTop();
    if (scrollDistance > 100) {
      $('.scroll-to-top').fadeIn();
    } else {
      $('.scroll-to-top').fadeOut();
    }
  });

  // Smooth scrolling using jQuery easing
  $(document).on('click', 'a.scroll-to-top', function(e) {
    const $anchor = $(this);
    $('html, body').stop().animate({
      scrollTop: ($($anchor.attr('href')).offset().top)
    }, 1000, 'easeInOutExpo');
    e.preventDefault();
  });

})(jQuery); // End of use strict
