$( '#topheader .navbar-nav a' ).on( 'click', function () {
	$( '#topheader .navbar-nav' ).find( 'li.active' ).removeClass( 'active' );
	$( this ).parent( 'li' ).addClass( 'active' );
});

$(".flashed-messages .alert").delay(4000).slideUp(500, function () {
 $(this).remove();
});
