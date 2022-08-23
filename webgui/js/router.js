//构造函数
function Router() {
    this.routes = {};
    this.currentUrl = '';
}
Router.prototype.route = function(path, callback) {
    this.routes[path] = callback || function(){};//给不同的hash设置不同的回调函数
};


Router.prototype.refresh = function() {
    // console.log(location.hash.slice(1));//获取到相应的hash值
    this.curUrl = location.hash.slice(1) || '/';//如果存在hash值则获取到，否则设置hash值为/

    // console.log(this.curUrl);
    if(this.curUrl&&this.curUrl!='/'){
        let func = this.routes[this.curUrl];//根据当前的hash值来调用相对应的回调函数

        if (func == undefined){
            func = defaultRoter
        }
        func(this.curUrl)
    }

};
Router.prototype.init = function() {
    window.addEventListener('load', this.refresh.bind(this), false);
    window.addEventListener('hashchange', this.refresh.bind(this), false);
    window.addEventListener('popstate',function (){location.reload()})
}
//给window对象挂载属性
window.Router = new Router();
window.Router.init();

function defaultRoter(curUrl){
    // console.log(curUrl)
    $("#app").html("")
    axios.get(curUrl).then(function (response) {
        // console.log(response.data)
        $("#app").html("<pre class=text-justify>"+ response.data +"</pre>")

        $("a").each(function(){
            $old_url = $(this).attr('href');
            // console.log($old_url)
            $new_url = '#'+ curUrl +$old_url;

            $(this).attr('href',$new_url);//changed this line
            // console.log($new_url)
        });

        $("a").addClass("text-success")
        $("a").addClass("font-weight-bold")
        $("a").css("font-size","20px")
        $("a").css("line-height","30px")
    }).catch(function (err){
        alert("ERROR:此程序未配置日志，如需配置参考stdout_logfile")
    })

}
