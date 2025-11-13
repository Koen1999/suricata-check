var script = document.createElement("script");

script.setAttribute("async", "");
script.setAttribute("src", "https://umami.suricata-check.teuwen.net/script.js");
script.setAttribute("data-website-id", "4a87d4af-7bc0-4ec0-8f6f-a69e03468b4d");
script.setAttribute("data-do-not-track", "true");
script.setAttribute("data-domains", "suricata-check.teuwen.net");

window.addEventListener('load', function () {
    document.body.appendChild(script);

    (() => {
        const name = 'internal-link-click';
        document.querySelectorAll('a').forEach(a => {
            if (a.host === window.location.host && !a.getAttribute('data-umami-event')) {
                a.setAttribute('data-umami-event', name);
                a.setAttribute('data-umami-event-source', window.location.href);
                a.setAttribute('data-umami-event-target', a.href);
            }
        });
    })();
    
    (() => {
        const name = 'outbound-link-click';
        document.querySelectorAll('a').forEach(a => {
            if (a.host !== window.location.host && !a.getAttribute('data-umami-event')) {
                a.setAttribute('data-umami-event', name);
                a.setAttribute('data-umami-event-source', window.location.href);
                a.setAttribute('data-umami-event-target', a.href);
            }
        });
    })();
});
