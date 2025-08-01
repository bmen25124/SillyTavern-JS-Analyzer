const path = require('path');
const TerserPlugin = require('terser-webpack-plugin');

const serverConfig = {
    devtool: false,
    target: 'node',
    entry: './src/index.ts',
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'index.js',
        libraryTarget: 'commonjs',
        libraryExport: 'default',
    },
    externals: {
        'tree-sitter': 'commonjs tree-sitter',
        'tree-sitter-javascript': 'commonjs tree-sitter-javascript',
    },
    resolve: {
        extensions: ['.ts', '.js'],
    },
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    optimization: {
        minimizer: [new TerserPlugin({
            extractComments: false,
        })],
    },
    plugins: [],
};

module.exports = [serverConfig];
